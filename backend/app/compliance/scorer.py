"""Compliance scoring: CVSS v3.1 base scores, per-subdomain grades and OWASP Top 10 (2025) status."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable

from app.compliance import categories, load_mapping
from app.models.audit import CategoryResult, CategoryStatus, ComplianceSummary, SubdomainResult
from app.models.finding import SEVERITY_RANK, PassiveFinding, Severity

# --------------------------------------------------------------------------- CVSS v3.1

_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_WEIGHTS = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup as defined in specification Appendix A."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_cvss_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError(f"not a CVSS v3.1 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        if not value:
            raise ValueError(f"malformed metric {part!r} in {vector!r}")
        metrics[key] = value
    missing = [m for m in _REQUIRED_METRICS if m not in metrics]
    if missing:
        raise ValueError(f"vector {vector!r} missing base metrics {missing}")
    if metrics["S"] not in ("U", "C"):
        raise ValueError(f"invalid scope in {vector!r}")
    return metrics


def cvss31_base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score for a vector string."""
    m = parse_cvss_vector(vector)
    try:
        av = _CVSS_WEIGHTS["AV"][m["AV"]]
        ac = _CVSS_WEIGHTS["AC"][m["AC"]]
        ui = _CVSS_WEIGHTS["UI"][m["UI"]]
        pr = _PR_WEIGHTS[m["S"]][m["PR"]]
        c = _CVSS_WEIGHTS["C"][m["C"]]
        i = _CVSS_WEIGHTS["I"][m["I"]]
        a = _CVSS_WEIGHTS["A"][m["A"]]
    except KeyError as exc:
        raise ValueError(f"invalid metric value in {vector!r}") from exc

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def cvss_severity(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# --------------------------------------------------------------------------- scoring

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
REPEAT_WEIGHT_FACTOR = 0.25  # additional instances of the same rule on one host
MAX_REPEAT_PENALTY_INSTANCES = 4

GRADE_THRESHOLDS: list[tuple[int, str]] = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]

# Coverage levels for which an absence of findings legitimately counts as a pass.
_PASSABLE_COVERAGE = {"high", "partial"}


def grade_for(score: int | None) -> str:
    if score is None:
        return "N/A"
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def score_findings(findings: Iterable[PassiveFinding]) -> int:
    """Score 0-100: start at 100, deduct per unique rule, with damped penalties for repeats."""
    per_rule: dict[str, list[PassiveFinding]] = defaultdict(list)
    for finding in findings:
        per_rule[finding.rule_id].append(finding)

    penalty = 0.0
    for instances in per_rule.values():
        weight = SEVERITY_WEIGHTS[max(instances, key=lambda f: f.severity.rank).severity]
        repeats = min(len(instances) - 1, MAX_REPEAT_PENALTY_INSTANCES)
        penalty += weight + weight * REPEAT_WEIGHT_FACTOR * repeats
    return max(0, round(100 - penalty))


def severity_counts(findings: Iterable[PassiveFinding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def _status_for(findings: list[PassiveFinding], coverage: str) -> CategoryStatus:
    if coverage == "manual":
        return CategoryStatus.MANUAL_REVIEW
    if not findings:
        return CategoryStatus.PASS if coverage in _PASSABLE_COVERAGE else CategoryStatus.MANUAL_REVIEW
    worst = max(f.severity.rank for f in findings)
    if worst >= SEVERITY_RANK[Severity.MEDIUM]:
        return CategoryStatus.FAIL
    if worst == SEVERITY_RANK[Severity.LOW]:
        return CategoryStatus.WARNING
    # Informational-only findings do not break compliance on their own.
    return CategoryStatus.PASS if coverage in _PASSABLE_COVERAGE else CategoryStatus.MANUAL_REVIEW


def _max_severity(findings: list[PassiveFinding]) -> Severity | None:
    if not findings:
        return None
    return max(findings, key=lambda f: f.severity.rank).severity


def categorize(findings: list[PassiveFinding], reachable: bool = True) -> list[CategoryResult]:
    """Evaluate each OWASP Top 10 (2025) category for one subdomain."""
    results: list[CategoryResult] = []
    for cat_id, meta in categories().items():
        in_cat = [f for f in findings if cat_id in f.owasp]
        if reachable:
            status = _status_for(in_cat, meta["coverage"])
        else:
            status = CategoryStatus.MANUAL_REVIEW
        results.append(
            CategoryResult(
                id=cat_id,
                name=meta["name"],
                status=status,
                coverage=meta["coverage"],
                finding_count=len(in_cat),
                max_severity=_max_severity(in_cat),
                rule_ids=sorted({f.rule_id for f in in_cat}),
            )
        )
    return results


def apply_scores(result: SubdomainResult) -> SubdomainResult:
    """Populate score, grade, severity counts and category results on a subdomain result in place."""
    result.findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.url))
    result.severity_counts = severity_counts(result.findings)
    result.categories = categorize(result.findings, reachable=result.reachable)
    if result.reachable:
        result.score = score_findings(result.findings)
    else:
        result.score = None
    result.grade = grade_for(result.score)
    return result


_STATUS_ORDER = {
    CategoryStatus.FAIL: 3,
    CategoryStatus.WARNING: 2,
    CategoryStatus.PASS: 1,
    CategoryStatus.MANUAL_REVIEW: 0,
}


def summarize(subdomains: list[SubdomainResult]) -> ComplianceSummary:
    """Aggregate per-subdomain results into an engagement-wide compliance summary."""
    reachable = [s for s in subdomains if s.reachable]
    all_findings = [f for s in subdomains for f in s.findings]

    scores = [s.score for s in reachable if s.score is not None]
    overall = round(sum(scores) / len(scores)) if scores else None

    grade_dist = Counter(s.grade for s in subdomains)
    grade_distribution = {g: grade_dist.get(g, 0) for g in ("A", "B", "C", "D", "F", "N/A")}

    cat_meta = categories()
    aggregate: list[CategoryResult] = []
    for cat_id, meta in cat_meta.items():
        per_sub = [c for s in reachable for c in s.categories if c.id == cat_id]
        in_cat = [f for f in all_findings if cat_id in f.owasp]
        if meta["coverage"] == "manual" or not per_sub:
            status = CategoryStatus.MANUAL_REVIEW
        else:
            status = max((c.status for c in per_sub), key=lambda st: _STATUS_ORDER[st])
        evaluable = [c for c in per_sub if c.status != CategoryStatus.MANUAL_REVIEW]
        pass_rate = (
            round(sum(1 for c in evaluable if c.status == CategoryStatus.PASS) / len(evaluable), 4)
            if evaluable
            else None
        )
        aggregate.append(
            CategoryResult(
                id=cat_id,
                name=meta["name"],
                status=status,
                coverage=meta["coverage"],
                finding_count=len(in_cat),
                max_severity=_max_severity(in_cat),
                rule_ids=sorted({f.rule_id for f in in_cat}),
                pass_rate=pass_rate,
            )
        )

    rules = load_mapping()["rules"]
    rule_hosts: dict[str, set[str]] = defaultdict(set)
    rule_counts: Counter[str] = Counter()
    for f in all_findings:
        rule_hosts[f.rule_id].add(f.subdomain)
        rule_counts[f.rule_id] += 1
    top_rules = [
        {
            "rule_id": rule_id,
            "title": rules.get(rule_id, {}).get("title", rule_id),
            "severity": rules.get(rule_id, {}).get("severity", "info"),
            "count": count,
            "subdomains": len(rule_hosts[rule_id]),
        }
        for rule_id, count in sorted(
            rule_counts.items(),
            key=lambda kv: (-SEVERITY_RANK[Severity(rules.get(kv[0], {}).get("severity", "info"))], -kv[1]),
        )[:10]
    ]

    return ComplianceSummary(
        overall_score=overall,
        grade=grade_for(overall),
        subdomains_total=len(subdomains),
        subdomains_reachable=len(reachable),
        total_findings=len(all_findings),
        severity_counts=severity_counts(all_findings),
        grade_distribution=grade_distribution,
        categories=aggregate,
        top_rules=top_rules,
    )
