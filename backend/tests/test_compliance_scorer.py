"""Tests for CVSS scoring, grading, OWASP Top 10 (2025) category status, mapping integrity and exporters."""

from __future__ import annotations

import csv
import io
import json
import re

import pytest

from app.checks import ALL_CHECKS
from app.compliance import categories, get_rule, load_mapping
from app.compliance.scorer import (
    apply_scores,
    categorize,
    cvss31_base_score,
    cvss_severity,
    grade_for,
    parse_cvss_vector,
    score_findings,
    summarize,
)
from app.models.audit import AuditResult, CategoryStatus, SubdomainResult
from app.models.finding import Confidence, PassiveFinding, Severity
from app.reporting.exporter import FORMATS, build_sarif, export_csv, render
from tests.conftest import NOW


def make_finding(rule_id: str, subdomain: str = "a.example.com", evidence: str = "x") -> PassiveFinding:
    rule = get_rule(rule_id)
    url = f"https://{subdomain}/"
    return PassiveFinding(
        id=PassiveFinding.make_id(rule_id, subdomain, url, evidence),
        rule_id=rule_id,
        title=rule["title"],
        severity=Severity(rule["severity"]),
        confidence=Confidence(rule["confidence"]),
        subdomain=subdomain,
        url=url,
        description=rule["description"],
        evidence=evidence,
        remediation=rule["remediation"],
        cwe=rule["cwe"],
        wstg=rule.get("wstg"),
        owasp=rule["owasp"],
        cvss_vector=rule["cvss_vector"],
        cvss_score=cvss31_base_score(rule["cvss_vector"]),
    )


def make_subdomain(name: str, rule_list: list[str], reachable: bool = True) -> SubdomainResult:
    result = SubdomainResult(
        subdomain=name, reachable=reachable, findings=[make_finding(r, name, f"{r}-{i}") for i, r in enumerate(rule_list)]
    )
    return apply_scores(result)


# --------------------------------------------------------------------------- CVSS v3.1


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.2),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss31_reference_scores(vector, expected):
    assert cvss31_base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
)
def test_cvss_rejects_invalid_vectors(vector):
    with pytest.raises(ValueError):
        cvss31_base_score(vector)


def test_cvss_severity_bands():
    assert [cvss_severity(s) for s in (0, 3.9, 4.0, 6.9, 7.0, 9.0)] == ["none", "low", "medium", "medium", "high", "critical"]


# --------------------------------------------------------------------------- mapping integrity


def test_every_declared_rule_is_mapped_and_every_mapping_has_a_check():
    declared = {rule for cls in ALL_CHECKS for rule in cls.rule_ids}
    mapped = set(load_mapping()["rules"])
    assert declared == mapped


def test_mapping_entries_are_complete_and_valid():
    category_ids = set(categories())
    assert category_ids == {f"A{n:02d}:2025" for n in range(1, 11)}
    for rule_id, rule in load_mapping()["rules"].items():
        assert re.fullmatch(r"CWE-\d+", rule["cwe"]), rule_id
        assert rule["owasp"] and set(rule["owasp"]) <= category_ids, rule_id
        assert rule["severity"] in {s.value for s in Severity}, rule_id
        assert rule["confidence"] in {c.value for c in Confidence}, rule_id
        assert rule["wstg"] is None or re.fullmatch(r"WSTG-[A-Z]{4}-\d{2}", rule["wstg"]), rule_id
        assert rule["description"] and rule["remediation"] and rule["title"], rule_id
        parse_cvss_vector(rule["cvss_vector"])
        assert all(ref.startswith("https://") for ref in rule.get("references", [])), rule_id


def test_categories_and_modules_carry_drilldown_content():
    mapping = load_mapping()
    for cat_id, cat in mapping["categories"].items():
        assert cat["description"] and cat["passive_scope"], cat_id
        assert cat["manual_tests"], cat_id
        for test in cat["manual_tests"]:
            assert test["title"], cat_id
            assert test["wstg"] is None or re.fullmatch(r"WSTG-[A-Z]{4}-\d{2}", test["wstg"]), cat_id
    for rule_id, rule in mapping["rules"].items():
        assert mapping["modules"][rule["check"]]["method"], rule_id


def test_a09_is_never_marked_passable():
    assert categories()["A09:2025"]["coverage"] == "manual"


# --------------------------------------------------------------------------- scoring & grades


@pytest.mark.parametrize(
    ("score", "grade"), [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (75, "C"), (60, "D"), (59, "F"), (0, "F"), (None, "N/A")]
)
def test_grade_thresholds(score, grade):
    assert grade_for(score) == grade


def test_clean_host_scores_100():
    assert score_findings([]) == 100


def test_score_deducts_by_severity():
    # high 15 + medium 8 + low 3 + info 0 = 26
    findings = [make_finding(r) for r in ("TLS-NO-HTTPS", "HDR-CSP-MISSING", "HDR-XCTO-MISSING", "DISC-EMAIL")]
    assert score_findings(findings) == 74


def test_repeated_rule_instances_are_damped():
    single = score_findings([make_finding("CKE-NO-SECURE", evidence="a")])
    many = score_findings([make_finding("CKE-NO-SECURE", evidence=str(i)) for i in range(20)])
    assert single == 92
    # first instance 8 + at most 4 repeats * 8 * 0.25 = 16 total penalty
    assert many == 84


def test_score_never_negative():
    rules = [r for r, meta in load_mapping()["rules"].items() if meta["severity"] in ("high", "medium")]
    assert score_findings([make_finding(r) for r in rules]) == 0


# --------------------------------------------------------------------------- category status


def _status(results, cat_id):
    return next(c for c in results if c.id == cat_id).status


def test_clean_host_category_statuses():
    results = categorize([])
    assert _status(results, "A02:2025") == CategoryStatus.PASS
    assert _status(results, "A04:2025") == CategoryStatus.PASS
    # Passive indicators only -> cannot claim a pass for injection
    assert _status(results, "A05:2025") == CategoryStatus.MANUAL_REVIEW
    assert _status(results, "A09:2025") == CategoryStatus.MANUAL_REVIEW


def test_category_fail_warning_and_info_only():
    results = categorize([make_finding("HDR-HSTS-MISSING"), make_finding("CKE-NO-SAMESITE"), make_finding("CORS-WILDCARD")])
    assert _status(results, "A04:2025") == CategoryStatus.FAIL  # medium
    assert _status(results, "A07:2025") == CategoryStatus.WARNING  # low only
    assert _status(results, "A01:2025") == CategoryStatus.PASS  # informational only
    a04 = next(c for c in results if c.id == "A04:2025")
    assert a04.finding_count == 1 and a04.max_severity == Severity.MEDIUM and a04.rule_ids == ["HDR-HSTS-MISSING"]


def test_unreachable_host_is_manual_review_everywhere():
    sub = make_subdomain("down.example.com", [], reachable=False)
    assert sub.score is None and sub.grade == "N/A"
    assert {c.status for c in sub.categories} == {CategoryStatus.MANUAL_REVIEW}


def test_finding_mapped_to_multiple_categories_counts_in_each():
    results = categorize([make_finding("HDR-CSP-MISSING")])
    assert _status(results, "A02:2025") == CategoryStatus.FAIL
    assert _status(results, "A05:2025") == CategoryStatus.FAIL


# --------------------------------------------------------------------------- summary


def test_summary_aggregates_subdomains():
    subs = [
        make_subdomain("a.example.com", []),
        make_subdomain("b.example.com", ["HDR-CSP-MISSING", "HDR-XCTO-MISSING"]),
        make_subdomain("c.example.com", [], reachable=False),
    ]
    summary = summarize(subs)
    assert summary.subdomains_total == 3 and summary.subdomains_reachable == 2
    assert summary.overall_score == round((100 + 89) / 2)
    assert summary.grade == "A"
    assert summary.total_findings == 2
    assert summary.severity_counts == {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0}
    assert summary.grade_distribution["A"] == 1 and summary.grade_distribution["B"] == 1 and summary.grade_distribution["N/A"] == 1
    a02 = next(c for c in summary.categories if c.id == "A02:2025")
    assert a02.status == CategoryStatus.FAIL and a02.pass_rate == 0.5
    assert next(c for c in summary.categories if c.id == "A09:2025").status == CategoryStatus.MANUAL_REVIEW
    assert summary.top_rules[0]["rule_id"] == "HDR-CSP-MISSING"


def test_summary_with_no_reachable_hosts():
    summary = summarize([make_subdomain("x.example.com", [], reachable=False)])
    assert summary.overall_score is None and summary.grade == "N/A"


# --------------------------------------------------------------------------- exporters


@pytest.fixture
def audit() -> AuditResult:
    subs = [
        make_subdomain("a.example.com", ["HDR-CSP-MISSING", "TLS-NO-REDIRECT"]),
        make_subdomain("b.example.com", ["DISC-SERVER-VERSION"]),
    ]
    subs[1].findings[0].evidence = "=HYPERLINK(\"http://evil\")"
    return AuditResult(id="t1", authorization_ref="ENG-TEST", created_at=NOW, completed_at=NOW,
                       subdomains=subs, summary=summarize(subs))


def test_sarif_structure(audit):
    sarif = build_sarif(audit)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted({"HDR-CSP-MISSING", "TLS-NO-REDIRECT", "DISC-SERVER-VERSION"})
    assert len(run["results"]) == 3
    for result in run["results"]:
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("https://")
    csp_rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "HDR-CSP-MISSING")
    assert "A02:2025" in csp_rule["properties"]["tags"] and "CWE-693" in csp_rule["properties"]["tags"]
    assert float(csp_rule["properties"]["security-severity"]) == cvss31_base_score(get_rule("HDR-CSP-MISSING")["cvss_vector"])


def test_csv_neutralises_formula_injection(audit):
    rows = list(csv.DictReader(io.StringIO(export_csv(audit).decode("utf-8-sig"))))
    assert len(rows) == 3
    assert rows[0]["severity"] == "medium"
    evil = next(r for r in rows if r["rule_id"] == "DISC-SERVER-VERSION")
    assert evil["evidence"].startswith("'=")


def test_single_subdomain_export_is_scoped(audit):
    payload = json.loads(render(audit, "json", subdomain="b.example.com").content)
    assert [s["subdomain"] for s in payload["subdomains"]] == ["b.example.com"]
    assert payload["summary"]["total_findings"] == 1


@pytest.mark.parametrize("fmt", [f for f in FORMATS if f != "pdf"])
def test_all_text_formats_render(audit, fmt):
    artifact = render(audit, fmt)
    assert artifact.content and artifact.extension == fmt


def test_html_report_escapes_evidence(audit):
    audit.subdomains[0].findings[0].evidence = "<script>alert(1)</script>"
    html = render(audit, "html").content.decode()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "A09:2025" in html


def test_pdf_export_returns_pdf_or_html_fallback(audit):
    artifact = render(audit, "pdf")
    if artifact.extension == "pdf":
        assert artifact.content.startswith(b"%PDF")
    else:
        assert artifact.fallback_note and b"<html" in artifact.content
