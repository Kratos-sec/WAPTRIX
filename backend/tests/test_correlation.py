"""Cross-tool correlation and the voting model (paper Section III-D, eq. 1)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.checks.base import rule_finding  # noqa: E402
from app.compliance.scorer import summarize  # noqa: E402
from app.correlation import correlate  # noqa: E402
from app.models.audit import SubdomainResult  # noqa: E402
from app.models.finding import Confidence, PassiveFinding, Severity  # noqa: E402

HOST = "app.example.com"
URL = f"https://{HOST}/"


def builtin(rule_id: str, evidence: str = "e", url: str = URL) -> PassiveFinding:
    return rule_finding(rule_id, HOST, url, evidence)


def tool(rule_id: str, source: str, *, cwe: str, confidence: Confidence, severity: Severity,
         url: str = URL, evidence: str = "e") -> PassiveFinding:
    return PassiveFinding(
        id=PassiveFinding.make_id(rule_id, HOST, url, evidence), rule_id=rule_id, title=rule_id,
        severity=severity, confidence=confidence, subdomain=HOST, url=url, description="d",
        remediation="r", cwe=cwe, sources=[source], evidence=evidence,
    )


# --------------------------------------------------------------------------- lone-engine admission


def test_lone_builtin_certain_and_firm_admit_tentative_queues():
    # No tools ran: a finding's confidence is its own certainty, so firm clears τ=0.55 but tentative does not.
    certain = correlate([builtin("HDR-CSP-MISSING")], {"waptrix"})  # certain
    assert [f.correlation_score for f in certain.admitted] == [1.0] and not certain.queued

    firm = correlate([builtin("HDR-XFO-MISSING")], {"waptrix"})  # firm -> 0.72
    assert firm.admitted and firm.admitted[0].correlation_score == 0.72

    tentative = correlate([builtin("FORM-NO-CSRF-TOKEN")], {"waptrix"})  # tentative -> 0.45
    assert not tentative.admitted and tentative.queued[0].correlation_score == 0.45
    assert tentative.queued[0].correlation.admitted is False


# --------------------------------------------------------------------------- agreement and silence


def test_agreement_merges_group_and_unions_engines():
    both = correlate(
        [builtin("HDR-CSP-MISSING"), tool("HDR-CSP-MISSING", "zap", cwe="CWE-693",
                                          confidence=Confidence.CERTAIN, severity=Severity.MEDIUM)],
        {"waptrix", "zap"},
    )
    assert len(both.admitted) == 1
    rep = both.admitted[0]
    assert rep.sources == ["waptrix", "zap"]
    assert set(rep.correlation.detectors) == {"waptrix", "zap"} and rep.correlation.score == 1.0


def test_silent_capable_peer_lowers_confidence_below_threshold():
    # A firm built-in header finding drops to the re-test queue when a header-capable engine ran silent.
    out = correlate([builtin("HDR-XFO-MISSING")], {"waptrix", "zap"})
    assert not out.admitted and out.queued
    info = out.queued[0].correlation
    assert info.detectors == ["waptrix"] and info.applicable == ["waptrix", "zap"] and info.silent == ["zap"]
    assert info.score < 0.55


# --------------------------------------------------------------------------- active confirmation (γ·v)


def test_active_confirmation_merges_and_admits_candidate():
    param = f"{URL}p?id=1"
    wapiti = tool("WAPITI-SQLI", "wapiti", cwe="CWE-89", confidence=Confidence.TENTATIVE,
                  severity=Severity.CRITICAL, url=param, evidence="wapiti")
    sqlmap = tool("SQLMAP-GET-ID", "sqlmap", cwe="CWE-89", confidence=Confidence.CERTAIN,
                  severity=Severity.CRITICAL, url=param, evidence="sqlmap")

    alone = correlate([wapiti.model_copy(deep=True)], {"waptrix", "wapiti"})
    assert not alone.admitted  # 0.45 < τ

    confirmed = correlate([wapiti, sqlmap], {"waptrix", "wapiti", "sqlmap"})
    assert len(confirmed.admitted) == 1
    rep = confirmed.admitted[0]
    assert rep.correlation.confirmed is True and set(rep.correlation.detectors) == {"wapiti", "sqlmap"}


def test_injection_point_separates_distinct_parameters():
    a = tool("WAPITI-SQLI", "wapiti", cwe="CWE-89", confidence=Confidence.CERTAIN,
             severity=Severity.CRITICAL, url=f"{URL}p?id=1", evidence="a")
    b = tool("WAPITI-SQLI", "wapiti", cwe="CWE-89", confidence=Confidence.CERTAIN,
             severity=Severity.CRITICAL, url=f"{URL}p?name=x", evidence="b")
    out = correlate([a, b], {"waptrix", "wapiti"})
    assert len(out.admitted) == 2


# --------------------------------------------------------------------------- de-duplication rules


def test_multi_instance_libraries_stay_separate():
    libs = correlate(
        [builtin("JS-VULNERABLE-LIBRARY", "jquery 1.0"), builtin("JS-VULNERABLE-LIBRARY", "lodash 2.0")],
        {"waptrix"},
    )
    assert len(libs.findings) == 2


def test_generic_httponly_votes_with_session_variant():
    out = correlate(
        [builtin("CKE-SESSION-NO-HTTPONLY", "sid"),
         tool("CKE-NO-HTTPONLY", "zap", cwe="CWE-1004", confidence=Confidence.FIRM, severity=Severity.MEDIUM)],
        {"waptrix", "zap"},
    )
    assert len(out.findings) == 1
    rep = out.findings[0]
    assert rep.rule_id == "CKE-SESSION-NO-HTTPONLY" and rep.sources == ["waptrix", "zap"]


# --------------------------------------------------------------------------- knowledge base enrichment


def test_knowledge_base_fills_cvss_and_owasp_for_tool_alert():
    alert = tool("NIKTO-OUTDATED", "nikto", cwe="CWE-1104", confidence=Confidence.CERTAIN,
                 severity=Severity.HIGH)
    alert.cvss_vector = None
    alert.cvss_score = None
    alert.owasp = []
    out = correlate([alert], {"waptrix", "nikto"})
    rep = out.findings[0]
    assert rep.cvss_vector is not None and rep.cvss_score == 7.5
    assert rep.owasp  # populated from the CWE index


# --------------------------------------------------------------------------- threshold override + summary


def test_tau_override_admits_tentative(monkeypatch):
    monkeypatch.setenv("WAPTRIX_VOTE_TAU", "0.4")
    out = correlate([builtin("FORM-NO-CSRF-TOKEN")], {"waptrix"})
    assert out.admitted and not out.queued


def test_summary_counts_retest_queue():
    queued = correlate([builtin("FORM-NO-CSRF-TOKEN")], {"waptrix"}).queued
    sub = SubdomainResult(subdomain=HOST, reachable=True, findings=[], retest_queue=queued)
    summary = summarize([sub])
    assert summary.total_retest == 1 and summary.total_findings == 0
