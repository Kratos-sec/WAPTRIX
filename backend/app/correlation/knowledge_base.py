"""Knowledge base enrichment (paper gap G4): every surviving finding carries CWE, a CVSS v3.1 vector
and an OWASP Top 10 (2025) category before it reaches the reporting layer.

Built-in rules already arrive fully mapped from ``owasp_2025_map.json``. Tool-only alerts
(``<TOOL>-<id>``) may lack an OWASP category or a CVSS vector; this module fills those gaps so the
report speaks one risk vocabulary regardless of which engine produced the finding. It never overwrites a
value a rule or adapter already set.
"""

from __future__ import annotations

from app.compliance import owasp_for_cwe
from app.compliance.scorer import cvss31_base_score
from app.models.finding import PassiveFinding, Severity

# Generic CVSS v3.1 base vectors used only as a fallback for tool alerts that carry a severity but no
# vector of their own. They are deliberate placeholders, not a claim of a precise impact assessment.
_SEVERITY_VECTOR: dict[Severity, str] = {
    Severity.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Severity.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Severity.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    Severity.LOW: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
}


def enrich(finding: PassiveFinding) -> PassiveFinding:
    """Fill missing OWASP category and CVSS vector/score in place, then return the finding."""
    if not finding.owasp and finding.cwe:
        finding.owasp = owasp_for_cwe(finding.cwe)
    if finding.cvss_vector is None:
        vector = _SEVERITY_VECTOR.get(finding.severity)
        if vector is not None:
            finding.cvss_vector = vector
            finding.cvss_score = cvss31_base_score(vector)
    elif finding.cvss_score is None:
        finding.cvss_score = cvss31_base_score(finding.cvss_vector)
    return finding
