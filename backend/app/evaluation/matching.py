"""Score a finding set against ground truth: TP / FP / FN, precision, recall, F1.

A finding matches a ground-truth entry when its CWE falls in the entry's CWE family and its URL path lies
under the entry's path. If the entry names a parameter and the finding's URL carries parameters, one of
them must be that parameter (a finding with no query string is allowed, since many engines report the
endpoint rather than the exact parameter). Each entry is credited at most once: further findings for an
already-credited entry are duplicates, neither TP nor FP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from app.correlation import profiles
from app.evaluation.ground_truth import GroundTruth, GroundTruthEntry
from app.models.finding import PassiveFinding, Severity


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    duplicates: int = 0
    excluded: int = 0
    matched: list[str] = field(default_factory=list)
    false_positives: list[PassiveFinding] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def _under(path: str, prefix: str) -> bool:
    if prefix == "/" or path == prefix:
        return True
    base = prefix.rstrip("/")
    return path == base or path.startswith(base + "/") or (prefix.endswith("/") and path.startswith(prefix))


def matches(entry: GroundTruthEntry, finding: PassiveFinding) -> bool:
    if not finding.cwe or finding.cwe not in entry.cwe:
        return False
    parts = urlsplit(finding.url)
    if not _under(parts.path or "/", entry.path):
        return False
    if entry.param:
        params = {key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
        if params and entry.param not in params:
            return False
    return True


def in_scope(finding: PassiveFinding, excluded_tags: set[str], min_severity: Severity) -> bool:
    """Findings below the severity floor, or in classes the lab cannot exhibit, are not scored."""
    if finding.severity.rank < min_severity.rank:
        return False
    return profiles.tag_for(finding.rule_id, finding.cwe or None) not in excluded_tags


def score(findings: list[PassiveFinding], truth: GroundTruth, excluded_tags: set[str] | None = None,
          min_severity: Severity = Severity.LOW) -> Score:
    excluded_tags = excluded_tags or set()
    result = Score()
    claimed: set[str] = set()
    # Score the most specific findings first, so a parameter-level report claims its entry before a
    # generic endpoint-level one does.
    ordered = sorted(findings, key=lambda f: (not urlsplit(f.url).query, -f.severity.rank, f.id))
    for finding in ordered:
        if not in_scope(finding, excluded_tags, min_severity):
            result.excluded += 1
            continue
        candidates = [e for e in truth.entries if matches(e, finding)]
        fresh = next((e for e in candidates if e.id not in claimed), None)
        if fresh is not None:
            claimed.add(fresh.id)
            result.tp += 1
            result.matched.append(fresh.id)
        elif candidates:
            result.duplicates += 1
        else:
            result.fp += 1
            result.false_positives.append(finding)
    result.fn = len(truth.entries) - result.tp
    return result


__all__ = ["Score", "score", "matches", "in_scope"]
