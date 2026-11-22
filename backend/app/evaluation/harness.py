"""Benchmark harness: collect runs against the lab, then score them into the paper's Table VII.

Two phases, so scoring can be repeated (new ground truth, adjudications, τ) without rescanning:

  collect   run the full WAPTrix workflow against every lab app, ``reps`` times, saving for each run the
            audit result *and* every raw pre-correlation finding (``<app>-r<k>.json``).
  evaluate  rebuild, from those files, the report set of each individual engine, of the naive union of
            the compared engines, of WAPTrix as run, and of WAPTrix with leave-one-app-out calibrated
            weights; score each against ground truth and take the median over repetitions.

Leave-one-app-out: for each held-out app, every engine's reliability weight w_i is set to its smoothed
precision (TP+1)/(TP+FP+2) on the other four apps, and the held-out app's raw findings are re-voted with
those weights. This answers the paper's own caveat that weights calibrated on the evaluation targets
inflate precision.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import statistics
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.correlation import canonical_key, correlate
from app.evaluation import lab_login
from app.evaluation.ground_truth import GroundTruth, load_ground_truth
from app.evaluation.matching import Score, score
from app.models.audit import AuditRequest, AuditResult
from app.models.finding import PassiveFinding, Severity

WAPTRIX = "WAPTrix (proposed)"
WAPTRIX_LOAO = "WAPTrix (leave-one-app-out weights)"
UNION = "Naive union"
BUILTIN = "waptrix"


# --------------------------------------------------------------------------- configuration


@dataclass
class LabApp:
    id: str
    name: str
    host: str
    version: str = ""
    stack: str = ""
    documented_total: int = 0
    seed_urls: list[str] = field(default_factory=list)  # paths with parameters to test directly


@dataclass
class LabConfig:
    root: Path
    authorization_ref: str
    scope_domain: str
    engines: dict[str, list[str]]  # display name -> adapter names that make up that engine
    passive_tools: list[str]
    active_tools: list[str]
    apps: list[LabApp]
    out_of_scope_tags: set[str] = field(default_factory=set)
    min_severity: Severity = Severity.LOW

    def app(self, app_id: str) -> LabApp:
        for app in self.apps:
            if app.id == app_id:
                return app
        raise KeyError(f"unknown lab app {app_id!r}; known: {', '.join(a.id for a in self.apps)}")


def load_config(lab_dir: Path) -> LabConfig:
    data = json.loads((lab_dir / "targets.json").read_text(encoding="utf-8"))
    scope = data["scope_domain"].lower()
    apps = [LabApp(**{k: v for k, v in raw.items() if k in LabApp.__dataclass_fields__}) for raw in data["apps"]]
    for app in apps:
        if not app.host.lower().endswith("." + scope):
            raise ValueError(f"lab app {app.id}: host {app.host} is outside scope domain {scope}")
    return LabConfig(
        root=lab_dir,
        authorization_ref=data["authorization_ref"],
        scope_domain=scope,
        engines=data["engines"],
        passive_tools=data.get("passive_tools", []),
        active_tools=data.get("active_tools", []),
        apps=apps,
        out_of_scope_tags=set(data.get("out_of_scope_tags", [])),
        min_severity=Severity(data.get("min_severity", "low")),
    )


# --------------------------------------------------------------------------- collect


def _resolves_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(ipaddress.ip_address(a).is_private for a in addresses)


AuditorFactory = Callable[..., Any]


def lab_request(config: LabConfig, app: LabApp, tool_timeout: float = 1800.0,
                cookie: str | None = None) -> AuditRequest:
    return AuditRequest(
        cookie=cookie,
        seed_urls=[f"http://{app.host}{path}" for path in app.seed_urls],
        subdomains=[app.host],
        authorization_ref=config.authorization_ref,
        scope_domains=[config.scope_domain],
        allow_private=True,  # lab containers live on a private Docker network
        tools=config.passive_tools,
        active=bool(config.active_tools),
        active_tools=config.active_tools,
        tool_timeout=tool_timeout,
        requests_per_second=10,
        max_endpoints=15,
    )


async def collect(config: LabConfig, out_dir: Path, apps: Iterable[str] | None = None, reps: int = 3,
                  auditor_factory: AuditorFactory | None = None, require_private: bool = True,
                  tool_timeout: float = 1800.0, log: Callable[[str], None] = print,
                  login: Callable[[str, str], str | None] | None = None,
                  save: Callable[[AuditResult], None] | None = None) -> list[Path]:
    """Run every selected app ``reps`` times and write one record per run.

    Active engines are pointed only at hosts under the lab scope domain, and (unless a test disables it)
    only when every host resolves to private addresses — i.e. the internal lab network, never the internet.
    """
    if auditor_factory is None:
        from app.engine.passive_auditor import PassiveAuditor

        auditor_factory = PassiveAuditor
        login = login or lab_login.login
    selected = [config.app(a) for a in apps] if apps else config.apps
    if require_private:
        public = [a.host for a in selected if not _resolves_private(a.host)]
        if public:
            raise RuntimeError(
                "refusing to scan: these lab hosts do not resolve to private lab addresses: " + ", ".join(public)
                + ". Run collect inside the api container with the lab stack up (docker-compose.lab.yml)."
            )
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for app in selected:
        for rep in range(1, reps + 1):
            log(f"[{app.id}] repetition {rep}/{reps}: scanning {app.host}")
            cookie = await asyncio.to_thread(login, app.id, app.host) if login else None
            if login and app.id in lab_login.RECIPES:
                log(f"[{app.id}] " + ("logged in, scanning with session" if cookie else "login FAILED, scanning unauthenticated"))
            auditor = auditor_factory(lab_request(config, app, tool_timeout, cookie))
            started = datetime.now(timezone.utc)
            audit: AuditResult = await auditor.run()
            duration = (datetime.now(timezone.utc) - started).total_seconds()
            record = {
                "app": app.id,
                "rep": rep,
                "started_at": started.isoformat(),
                "duration_s": round(duration, 1),
                "audit": json.loads(audit.model_dump_json()),
                "raw": {host: [json.loads(f.model_dump_json()) for f in raw]
                        for host, raw in auditor.raw_findings.items()},
            }
            if save is not None:
                save(audit)
            path = out_dir / f"{app.id}-r{rep}.json"
            path.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
            written.append(path)
            log(f"[{app.id}] repetition {rep}: {audit.summary.total_findings} findings in {duration / 60:.1f} min -> {path.name}")
    return written


# --------------------------------------------------------------------------- run records


@dataclass
class RunRecord:
    app: str
    rep: int
    duration_s: float
    audit: AuditResult
    raw: dict[str, list[PassiveFinding]]

    def engines_ran(self, host: str) -> set[str]:
        sub = next((s for s in self.audit.subdomains if s.subdomain == host), None)
        runs = sub.tool_runs if sub else []
        return {BUILTIN} | {r.tool for r in runs if r.succeeded}

    def tool_seconds(self, tools: Iterable[str]) -> float:
        wanted = set(tools)
        return sum(r.duration_s for s in self.audit.subdomains for r in s.tool_runs if r.tool in wanted)

    def ran_any(self, tools: Iterable[str]) -> bool:
        wanted = set(tools)
        return any(wanted & self.engines_ran(s.subdomain) for s in self.audit.subdomains)


def load_runs(run_dir: Path) -> list[RunRecord]:
    records = []
    for path in sorted(run_dir.glob("*-r*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        records.append(RunRecord(
            app=data["app"],
            rep=int(data["rep"]),
            duration_s=float(data.get("duration_s", 0.0)),
            audit=AuditResult.model_validate(data["audit"]),
            raw={host: [PassiveFinding.model_validate(f) for f in items] for host, items in data["raw"].items()},
        ))
    return records


# --------------------------------------------------------------------------- report sets


def _dedupe(findings: Iterable[PassiveFinding]) -> list[PassiveFinding]:
    seen: dict[tuple, PassiveFinding] = {}
    for f in findings:
        seen.setdefault(canonical_key(f), f)
    return list(seen.values())


def engine_set(record: RunRecord, tools: Iterable[str]) -> list[PassiveFinding]:
    """What an engine reports on its own: its raw findings, de-duplicated by canonical key."""
    wanted = set(tools)
    return _dedupe(f for raw in record.raw.values() for f in raw if wanted & set(f.sources))


def union_set(record: RunRecord, engines: dict[str, list[str]]) -> list[PassiveFinding]:
    """Naive union of the compared engines: everything any of them reported, de-duplicated, no voting."""
    return engine_set(record, [t for tools in engines.values() for t in tools])


def waptrix_set(record: RunRecord) -> list[PassiveFinding]:
    return [f for s in record.audit.subdomains for f in s.findings]


def revote_set(record: RunRecord, weights: dict[str, float], tau: float | None = None) -> list[PassiveFinding]:
    """Re-run the eq. 1 vote on the raw findings with the given weights; return the admitted set."""
    admitted: list[PassiveFinding] = []
    for host, raw in record.raw.items():
        outcome = correlate([f.model_copy(deep=True) for f in raw], record.engines_ran(host), weights=weights, tau=tau)
        admitted += outcome.admitted
    return admitted


def calibrate(records: list[RunRecord], truths: dict[str, GroundTruth], config: LabConfig) -> dict[str, float]:
    """Smoothed per-engine precision (TP+1)/(TP+FP+2) over the given runs — the w_i of eq. 1."""
    tally: dict[str, list[int]] = {}
    for record in records:
        truth = truths[record.app]
        engines = {t for raw in record.raw.values() for f in raw for t in f.sources}
        for engine in engines:
            s = score(engine_set(record, [engine]), truth, config.out_of_scope_tags, config.min_severity)
            tp_fp = tally.setdefault(engine, [0, 0])
            tp_fp[0] += s.tp
            tp_fp[1] += s.fp
    return {engine: round((tp + 1) / (tp + fp + 2), 4) for engine, (tp, fp) in sorted(tally.items())}


# --------------------------------------------------------------------------- evaluate


@dataclass
class Row:
    system: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    minutes: float | None = None
    ran: bool = True

    @property
    def precision(self) -> float:
        return Score(tp=self.tp, fp=self.fp, fn=self.fn).precision

    @property
    def recall(self) -> float:
        return Score(tp=self.tp, fp=self.fp, fn=self.fn).recall

    @property
    def f1(self) -> float:
        return Score(tp=self.tp, fp=self.fp, fn=self.fn).f1

    def as_dict(self) -> dict[str, Any]:
        return {"system": self.system, "tp": self.tp, "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 3), "recall": round(self.recall, 3), "f1": round(self.f1, 3),
                "mean_scan_minutes": None if self.minutes is None else round(self.minutes, 1), "ran": self.ran}


def _median_int(values: list[int]) -> int:
    return int(statistics.median_low(values)) if values else 0


def evaluate(config: LabConfig, records: list[RunRecord]) -> dict[str, Any]:
    if not records:
        raise ValueError("no run records found")
    apps = sorted({r.app for r in records}, key=lambda a: [x.id for x in config.apps].index(a)
                  if a in [x.id for x in config.apps] else 99)
    truths = {a: load_ground_truth(config.root, a, config.app(a).documented_total) for a in apps}
    by_app: dict[str, list[RunRecord]] = {a: sorted((r for r in records if r.app == a), key=lambda r: r.rep) for a in apps}

    loao_weights: dict[str, dict[str, float]] = {}
    for held_out in apps:
        training = [r for r in records if r.app != held_out]
        loao_weights[held_out] = calibrate(training, truths, config) if training else {}

    systems: list[tuple[str, Callable[[RunRecord], list[PassiveFinding]]]] = [
        *[(name, (lambda tools: lambda r: engine_set(r, tools))(tools)) for name, tools in config.engines.items()],
        (UNION, lambda r: union_set(r, config.engines)),
        (WAPTRIX, waptrix_set),
        (WAPTRIX_LOAO, lambda r: revote_set(r, loao_weights[r.app])),
    ]

    per_app: dict[str, dict[str, dict[str, Any]]] = {}
    totals = {name: Row(system=name) for name, _ in systems}
    minutes: dict[str, list[float]] = {name: [] for name, _ in systems}
    suppressed_by_app: dict[str, dict[str, int]] = {}

    for app in apps:
        truth = truths[app]
        per_app[app] = {}
        for name, build in systems:
            scores = [score(build(r), truth, config.out_of_scope_tags, config.min_severity) for r in by_app[app]]
            tp = _median_int([s.tp for s in scores])
            fp = _median_int([s.fp for s in scores])
            fn = _median_int([s.fn for s in scores])
            tools = config.engines.get(name)
            ran = all(r.ran_any(tools) for r in by_app[app]) if tools else True
            if tools:
                secs = statistics.median(r.tool_seconds(tools) for r in by_app[app])
            elif name == UNION:
                secs = statistics.median(r.tool_seconds([t for ts in config.engines.values() for t in ts])
                                         for r in by_app[app])
            else:
                secs = statistics.median(r.duration_s for r in by_app[app])
            minutes[name].append(secs / 60)
            row = Row(system=name, tp=tp, fp=fp, fn=fn, minutes=secs / 60, ran=ran)
            per_app[app][name] = row.as_dict()
            total = totals[name]
            total.tp, total.fp, total.fn = total.tp + tp, total.fp + fp, total.fn + fn
            total.ran = total.ran and ran
        suppressed_by_app[app] = {"union_fp": per_app[app][UNION]["fp"], "waptrix_fp": per_app[app][WAPTRIX]["fp"]}

    for name, row in totals.items():
        row.minutes = statistics.mean(minutes[name]) if minutes[name] else None

    union_fp, wap_fp = totals[UNION].fp, totals[WAPTRIX].fp
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "apps": apps,
        "repetitions": {a: len(by_app[a]) for a in apps},
        "ground_truth": {a: {"entries": len(t.entries), "documented_total": t.documented_total,
                             "adjudicated": sum(1 for e in t.entries if e.adjudicated), "partial": t.partial}
                         for a, t in truths.items()},
        "table": [totals[name].as_dict() for name, _ in systems],
        "per_app": per_app,
        "fp_suppression": {
            "union_fp": union_fp, "waptrix_fp": wap_fp,
            "reduction": round(1 - wap_fp / union_fp, 3) if union_fp else None,
            "by_app": suppressed_by_app,
        },
        "loao_weights": loao_weights,
        "scoring": {"out_of_scope_tags": sorted(config.out_of_scope_tags), "min_severity": config.min_severity.value,
                    "median_over_repetitions": True},
    }


# --------------------------------------------------------------------------- rendering


def _fmt(value: float | None, digits: int = 3) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def render_markdown(results: dict[str, Any]) -> str:
    gt = results["ground_truth"]
    total_gt = sum(g["entries"] for g in gt.values())
    lines = [
        "# WAPTrix benchmark results",
        "",
        f"Generated {results['generated_at']} · apps: {', '.join(results['apps'])} · "
        f"median of {', '.join(f'{a}×{n}' for a, n in results['repetitions'].items())} repetitions",
        "",
        f"## Consolidated detection performance ({total_gt} ground-truth {'entry' if total_gt == 1 else 'entries'})",
        "",
        "| Engine | TP | FP | FN | Precision | Recall | F1 | Mean scan time (min) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in results["table"]:
        name = row["system"] + ("" if row["ran"] else " (did not run)")
        lines.append(f"| {name} | {row['tp']} | {row['fp']} | {row['fn']} | {_fmt(row['precision'])} | "
                     f"{_fmt(row['recall'])} | {_fmt(row['f1'])} | {_fmt(row['mean_scan_minutes'], 1)} |")
    sup = results["fp_suppression"]
    lines += ["", "## False-positive suppression", ""]
    if sup["reduction"] is None:
        lines.append("The naive union produced no false positives, so there is nothing to suppress.")
    elif sup["reduction"] >= 0:
        lines.append(f"Correlation cut false positives from {sup['union_fp']} (naive union) to {sup['waptrix_fp']} "
                     f"(WAPTrix): a {sup['reduction'] * 100:.0f}% reduction.")
    else:
        lines.append(f"False positives rose from {sup['union_fp']} (naive union) to {sup['waptrix_fp']} (WAPTrix). "
                     "WAPTrix also reports built-in and confirmation-engine findings the union does not include; "
                     "check the per-application tables and results.json.")
    lines += ["", "## Per application", ""]
    for app in results["apps"]:
        g = gt[app]
        lines += [f"### {app} — {g['entries']} ground-truth entries"
                  + (f" (documented total {g['documented_total']}; partial)" if g["partial"] else ""), "",
                  "| Engine | TP | FP | FN | Precision | Recall | F1 |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for row in results["per_app"][app].values():
            lines.append(f"| {row['system']} | {row['tp']} | {row['fp']} | {row['fn']} | {_fmt(row['precision'])} | "
                         f"{_fmt(row['recall'])} | {_fmt(row['f1'])} |")
        lines.append("")
    partial = [a for a, g in gt.items() if g["partial"]]
    if partial:
        lines += ["## Caveats", "",
                  f"Ground truth is partial for {', '.join(partial)}: recall and FN are measured against the listed "
                  "entries, not the documented totals, and findings that are real but unlisted count as false "
                  "positives until they are adjudicated (lab/adjudication/<app>.json). These numbers are not yet "
                  "comparable with the paper's Table VII.", ""]
    lines += ["Scan time: per engine, the summed duration of its tool runs; naive union, the sum over the "
              "compared engines (run one after another); WAPTrix, the audit's wall-clock time with engines "
              "running concurrently.", ""]
    return "\n".join(lines)


def write_results(results: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "results.json"
    md_path = out_dir / "table.md"
    csv_path = out_dir / "table.csv"
    json_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(results), encoding="utf-8")
    header = "system,tp,fp,fn,precision,recall,f1,mean_scan_minutes\n"
    body = "".join(
        f"\"{r['system']}\",{r['tp']},{r['fp']},{r['fn']},{r['precision']},{r['recall']},{r['f1']},"
        f"{'' if r['mean_scan_minutes'] is None else r['mean_scan_minutes']}\n" for r in results["table"])
    csv_path.write_text(header + body, encoding="utf-8")
    return [json_path, md_path, csv_path]


def run_collect(config: LabConfig, out_dir: Path, **kwargs) -> list[Path]:
    return asyncio.run(collect(config, out_dir, **kwargs))


__all__ = [
    "LabConfig", "LabApp", "RunRecord", "load_config", "collect", "run_collect", "load_runs", "evaluate",
    "calibrate", "engine_set", "union_set", "waptrix_set", "revote_set", "render_markdown", "write_results",
    "WAPTRIX", "WAPTRIX_LOAO", "UNION",
]
