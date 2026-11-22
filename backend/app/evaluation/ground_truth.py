"""Ground truth and reviewer adjudication for the benchmark lab (paper Section III-E).

Ground truth comes from each project's solution documentation (``lab/ground_truth/<app>.json``). Findings
outside it are adjudicated by two reviewers (``lab/adjudication/<app>.json``); an adjudicated finding joins
the ground truth only when its verdict is ``tp`` and at least two distinct reviewers signed it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from app.compliance import normalize_cwe

# CWE classes that describe the same defect at different granularity. Scanners and solution guides rarely
# agree on the exact CWE (e.g. CWE-89 vs CWE-564 for SQL injection), so matching is by family.
CWE_FAMILIES: list[frozenset[str]] = [
    frozenset({"CWE-89", "CWE-564", "CWE-943"}),  # SQL / query injection
    frozenset({"CWE-79", "CWE-80", "CWE-83", "CWE-87"}),  # cross-site scripting
    frozenset({"CWE-77", "CWE-78"}),  # command injection
    frozenset({"CWE-22", "CWE-23", "CWE-73", "CWE-98"}),  # path traversal / file inclusion
    frozenset({"CWE-200", "CWE-538", "CWE-548"}),  # information exposure / directory listing
    frozenset({"CWE-601"}),  # open redirect
    frozenset({"CWE-611", "CWE-776"}),  # XXE
    frozenset({"CWE-918"}),  # SSRF
]


def cwe_family(cwe: str) -> frozenset[str]:
    for family in CWE_FAMILIES:
        if cwe in family:
            return family
    return frozenset({cwe})


@dataclass(frozen=True)
class GroundTruthEntry:
    id: str
    title: str
    cwe: frozenset[str]  # expanded to the CWE families of every listed CWE
    path: str
    method: str = "GET"
    param: str | None = None
    wstg: str | None = None
    adjudicated: bool = False


@dataclass
class GroundTruth:
    app: str
    documented_total: int
    complete: bool
    entries: list[GroundTruthEntry] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)  # adjudicated false positives (for the record)

    @property
    def partial(self) -> bool:
        return not self.complete or len(self.entries) < self.documented_total


def _entry(raw: dict, adjudicated: bool = False, fallback_id: str = "") -> GroundTruthEntry:
    cwes = raw.get("cwe") or []
    cwes = [cwes] if isinstance(cwes, str) else cwes
    expanded: set[str] = set()
    for value in cwes:
        normalized = normalize_cwe(value)
        if normalized:
            expanded |= cwe_family(normalized)
    if not expanded:
        raise ValueError(f"ground-truth entry {raw.get('id') or fallback_id!r} has no valid CWE")
    path = raw.get("path") or "/"
    if not path.startswith("/"):
        raise ValueError(f"ground-truth entry {raw.get('id') or fallback_id!r}: path must start with '/'")
    return GroundTruthEntry(
        id=raw.get("id") or fallback_id,
        title=raw.get("title") or raw.get("note") or "",
        cwe=frozenset(expanded),
        path=path,
        method=(raw.get("method") or "GET").upper(),
        param=raw.get("param") or None,
        wstg=raw.get("wstg"),
        adjudicated=adjudicated,
    )


def load_ground_truth(lab_dir: Path, app: str, documented_total: int | None = None) -> GroundTruth:
    gt_path = lab_dir / "ground_truth" / f"{app}.json"
    data = json.loads(gt_path.read_text(encoding="utf-8")) if gt_path.exists() else {"entries": []}
    entries = [_entry(raw) for raw in data.get("entries", [])]
    ids = [e.id for e in entries]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{gt_path}: duplicate ground-truth ids")

    truth = GroundTruth(
        app=app,
        documented_total=int(data.get("documented_total", documented_total or len(entries))),
        complete=bool(data.get("complete", False)),
        entries=entries,
    )

    adj_path = lab_dir / "adjudication" / f"{app}.json"
    if adj_path.exists():
        for i, raw in enumerate(json.loads(adj_path.read_text(encoding="utf-8")).get("entries", [])):
            reviewers = {str(r).strip().lower() for r in raw.get("reviewers", []) if str(r).strip()}
            if raw.get("verdict") == "tp" and len(reviewers) >= 2:
                truth.entries.append(_entry(raw, adjudicated=True, fallback_id=f"adj:{app}:{i + 1}"))
            elif raw.get("verdict") == "fp":
                truth.rejected.append(raw)
    return truth


__all__ = ["GroundTruth", "GroundTruthEntry", "load_ground_truth", "cwe_family", "CWE_FAMILIES"]
