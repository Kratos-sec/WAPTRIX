"""Benchmark harness: ground truth, matching, collect → evaluate, leave-one-app-out calibration."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import httpx
import pytest

from app.checks.base import rule_finding
from app.engine.passive_auditor import PassiveAuditor
from app.evaluation import harness
from app.evaluation.ground_truth import load_ground_truth
from app.evaluation.matching import matches, score
from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterResult, ToolAdapter
from tests.conftest import good_tls
from tests.test_passive_checks import StaticTLS

REPO_LAB = Path(__file__).resolve().parents[2] / "lab"


def _finding(url: str, cwe: str | int, severity=Severity.HIGH, rule="TOOL-X", source="wapiti") -> PassiveFinding:
    from app.compliance import normalize_cwe

    return PassiveFinding(
        id=PassiveFinding.make_id(rule, "a.waptrix.lab", url, str(cwe)), rule_id=rule, title="t", severity=severity,
        confidence=Confidence.FIRM, subdomain="a.waptrix.lab", url=url, description="d", evidence=str(cwe),
        remediation="r", cwe=normalize_cwe(cwe) or "", owasp=[], sources=[source])


def _write_lab(root: Path, ground_truth: dict[str, list[dict]], adjudication: dict[str, list[dict]] | None = None):
    (root / "ground_truth").mkdir(parents=True)
    (root / "adjudication").mkdir()
    targets = {
        "authorization_ref": "LAB-TEST-1", "scope_domain": "waptrix.lab",
        "engines": {"Nikto": ["nikto"], "Wapiti": ["wapiti"]},
        "passive_tools": [], "active_tools": ["nikto", "wapiti", "sqlmap"],
        "out_of_scope_tags": ["transport_tls", "headers"],
        "apps": [{"id": app, "name": app, "host": f"{app}.waptrix.lab", "documented_total": 3} for app in ground_truth],
    }
    (root / "targets.json").write_text(json.dumps(targets))
    for app, entries in ground_truth.items():
        (root / "ground_truth" / f"{app}.json").write_text(json.dumps(
            {"app": app, "documented_total": 3, "complete": False, "entries": entries}))
        (root / "adjudication" / f"{app}.json").write_text(json.dumps(
            {"app": app, "entries": (adjudication or {}).get(app, [])}))


# --------------------------------------------------------------------------- shipped lab files


def test_shipped_lab_config_and_ground_truth_load():
    config = harness.load_config(REPO_LAB)
    assert [a.id for a in config.apps] == ["dvwa", "juiceshop", "webgoat", "bwapp", "mutillidae"]
    assert sum(a.documented_total for a in config.apps) == 282  # paper Table VI / VII
    assert set(config.engines) == {"Nikto", "Nuclei", "Wapiti", "OWASP ZAP"}
    for app in config.apps:
        truth = load_ground_truth(REPO_LAB, app.id, app.documented_total)
        assert truth.documented_total == app.documented_total and truth.partial
    assert any(e.id == "dvwa-sqli" for e in load_ground_truth(REPO_LAB, "dvwa").entries)


def test_config_rejects_hosts_outside_scope(tmp_path):
    _write_lab(tmp_path, {"a": []})
    data = json.loads((tmp_path / "targets.json").read_text())
    data["apps"][0]["host"] = "example.com"
    (tmp_path / "targets.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="outside scope"):
        harness.load_config(tmp_path)


def test_adjudication_needs_two_reviewers(tmp_path):
    _write_lab(tmp_path, {"a": [{"id": "sqli", "cwe": "CWE-89", "path": "/search"}]}, {"a": [
        {"cwe": "CWE-79", "path": "/echo", "verdict": "tp", "reviewers": ["alice", "bob"]},
        {"cwe": "CWE-22", "path": "/dl", "verdict": "tp", "reviewers": ["alice", "Alice"]},
        {"cwe": "CWE-200", "path": "/x", "verdict": "fp", "reviewers": ["alice", "bob"]},
    ]})
    truth = load_ground_truth(tmp_path, "a")
    assert [e.id for e in truth.entries] == ["sqli", "adj:a:1"] and truth.entries[1].adjudicated
    assert len(truth.rejected) == 1


# --------------------------------------------------------------------------- matching


def test_matching_by_cwe_family_path_and_parameter(tmp_path):
    _write_lab(tmp_path, {"a": [{"id": "sqli", "cwe": "CWE-89", "path": "/search", "param": "q"},
                                {"id": "ftp", "cwe": "CWE-548", "path": "/ftp"}]})
    sqli, ftp = load_ground_truth(tmp_path, "a").entries
    assert matches(sqli, _finding("http://a.waptrix.lab/search?q=1", "CWE-564"))  # same family
    assert matches(sqli, _finding("http://a.waptrix.lab/search", 89))  # endpoint-level report allowed
    assert not matches(sqli, _finding("http://a.waptrix.lab/search?page=1", 89))  # wrong parameter
    assert not matches(sqli, _finding("http://a.waptrix.lab/search?q=1", 79))
    assert matches(ftp, _finding("http://a.waptrix.lab/ftp/legal.md", "CWE-200"))  # exposure family
    assert not matches(ftp, _finding("http://a.waptrix.lab/ftpx", 548))  # path boundary


def test_score_counts_tp_fp_fn_duplicates_and_exclusions(tmp_path):
    _write_lab(tmp_path, {"a": [{"id": "sqli", "cwe": "CWE-89", "path": "/search", "param": "q"},
                                {"id": "xss", "cwe": "CWE-79", "path": "/echo"}]})
    truth = load_ground_truth(tmp_path, "a")
    findings = [
        _finding("http://a.waptrix.lab/search", 89),
        _finding("http://a.waptrix.lab/search?q=1", 89, rule="TOOL-Y"),  # duplicate of the same entry
        _finding("http://a.waptrix.lab/admin", 200),  # false positive
        _finding("http://a.waptrix.lab/", 200, severity=Severity.INFO),  # below the severity floor
        rule_finding("TLS-NO-HTTPS", "a.waptrix.lab", "http://a.waptrix.lab/", "no tls"),  # out-of-scope class
    ]
    s = score(findings, truth, {"transport_tls"})
    assert (s.tp, s.fp, s.fn, s.duplicates, s.excluded) == (1, 1, 1, 1, 2)
    assert s.matched == ["sqli"] and s.precision == 0.5 and s.recall == 0.5


# --------------------------------------------------------------------------- collect → evaluate


PAGE = '<html><body><a href="/search?q=x">search</a></body></html>'


class FakeWapiti(ToolAdapter):
    name = "wapiti"

    async def execute(self, ctx, workdir):
        return AdapterResult(tool=self.name, findings=[self.unmapped(
            ctx, "sqli", "SQL Injection", Severity.HIGH, Confidence.TENTATIVE, 89, "maybe", "q=x'",
            url=f"http://{ctx.target.host}/search?q=x")])


class FakeNikto(ToolAdapter):
    name = "nikto"

    async def execute(self, ctx, workdir):
        return AdapterResult(tool=self.name, findings=[self.unmapped(
            ctx, "999", "Interesting file", Severity.MEDIUM, Confidence.TENTATIVE, 200, "noise", "/backup",
            url=f"http://{ctx.target.host}/backup")])


class FakeSqlmap(ToolAdapter):
    name = "sqlmap"
    per_endpoint = True

    async def execute(self, ctx, workdir):
        findings = []
        if "/search" in ctx.url:
            findings.append(self.unmapped(ctx, "GET-q", "SQL injection confirmed", Severity.CRITICAL,
                                          Confidence.CERTAIN, 89, "confirmed", "q injectable"))
        return AdapterResult(tool=self.name, findings=findings)


def _factory(request):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "https":
            return httpx.Response(502)
        return httpx.Response(200, html=PAGE) if req.url.path == "/" else httpx.Response(404)

    async def resolver(host):
        return ["10.10.0.5"]

    return PassiveAuditor(request, transport=httpx.MockTransport(handler), tls_inspector=StaticTLS(good_tls()),
                          resolver=resolver, adapters=[FakeWapiti(), FakeNikto(), FakeSqlmap()])


async def test_collect_refuses_hosts_off_the_private_lab_network(tmp_path, monkeypatch):
    _write_lab(tmp_path / "lab", {"a": []})
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))])
    with pytest.raises(RuntimeError, match="refusing to scan"):
        await harness.collect(harness.load_config(tmp_path / "lab"), tmp_path / "runs", auditor_factory=_factory)


async def test_collect_then_evaluate_produces_table_vii(tmp_path, monkeypatch):
    lab = tmp_path / "lab"
    gt = [{"id": "sqli", "cwe": "CWE-89", "path": "/search", "param": "q"},
          {"id": "xss", "cwe": "CWE-79", "path": "/echo"}]
    _write_lab(lab, {"a": gt, "b": gt})
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: [(None, None, None, None, ("172.20.0.4", 0))])
    config = harness.load_config(lab)

    paths = await harness.collect(config, tmp_path / "runs", reps=2, auditor_factory=_factory, log=lambda m: None)
    assert sorted(p.name for p in paths) == ["a-r1.json", "a-r2.json", "b-r1.json", "b-r2.json"]
    record = json.loads(paths[0].read_text())
    assert {"audit", "raw", "duration_s"} <= set(record) and record["raw"]["a.waptrix.lab"]

    records = harness.load_runs(tmp_path / "runs")
    results = harness.evaluate(config, records)
    rows = {r["system"]: r for r in results["table"]}
    assert list(rows) == ["Nikto", "Wapiti", harness.UNION, harness.WAPTRIX, harness.WAPTRIX_LOAO]

    # Each engine alone: Wapiti finds the SQLi on both apps, Nikto only noise.
    assert (rows["Wapiti"]["tp"], rows["Wapiti"]["fp"], rows["Wapiti"]["fn"]) == (2, 0, 2)
    assert (rows["Nikto"]["tp"], rows["Nikto"]["fp"]) == (0, 2)
    # Naive union keeps Nikto's noise; WAPTrix votes it out while sqlmap's confirmation keeps the SQLi.
    assert (rows[harness.UNION]["tp"], rows[harness.UNION]["fp"]) == (2, 2)
    assert rows[harness.WAPTRIX]["tp"] == 2 and rows[harness.WAPTRIX]["fp"] < rows[harness.UNION]["fp"]
    assert results["fp_suppression"]["reduction"] > 0
    # Leave-one-app-out: weights for app a come from app b only, and are smoothed precisions.
    assert results["loao_weights"]["a"]["nikto"] == round(1 / 4, 4)  # (0+1)/(0+2+2): 2 FP over b's 2 reps
    assert rows[harness.WAPTRIX_LOAO]["tp"] == 2

    written = harness.write_results(results, tmp_path / "out")
    md = (tmp_path / "out" / "table.md").read_text()
    assert "| Wapiti | 2 | 0 | 2 |" in md and "partial" in md
    assert (tmp_path / "out" / "table.csv").read_text().startswith("system,tp,fp,fn")
    assert len(written) == 3


def test_calibrate_is_smoothed_precision(tmp_path):
    _write_lab(tmp_path, {"a": [{"id": "sqli", "cwe": "CWE-89", "path": "/search"}]})
    config = harness.load_config(tmp_path)
    from app.models.audit import AuditResult

    audit = AuditResult(id="x", authorization_ref="LAB-TEST-1", created_at="2026-01-01T00:00:00Z")
    record = harness.RunRecord(app="a", rep=1, duration_s=1, audit=audit, raw={"a.waptrix.lab": [
        _finding("http://a.waptrix.lab/search", 89, source="wapiti"),
        _finding("http://a.waptrix.lab/x", 200, source="wapiti", rule="TOOL-Z"),
        _finding("http://a.waptrix.lab/y", 200, source="nikto", rule="TOOL-N"),
    ]})
    weights = harness.calibrate([record], {"a": load_ground_truth(tmp_path, "a")}, config)
    assert weights == {"nikto": round(1 / 3, 4), "wapiti": 0.5}
