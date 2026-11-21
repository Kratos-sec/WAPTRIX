"""Canonical passive finding schema shared by every check, exporter and the API."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self]


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(str, Enum):
    """Burp-style confidence levels."""

    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


class CorrelationInfo(BaseModel):
    """Cross-tool voting outcome for one finding (paper eq. 1). Explains the confidence score."""

    score: float = Field(description="Weighted agreement score C(f)")
    threshold: float = Field(description="Admission threshold τ in force for this run")
    admitted: bool = Field(description="True when C(f) ≥ τ; False findings go to the re-test queue")
    confirmed: bool = Field(default=False, description="An active confirmation adapter reproduced it (v=1)")
    tag: str = Field(description="Capability class the finding was voted on, e.g. headers or injection")
    detectors: list[str] = Field(default_factory=list, description="Engines that reported it (the set T)")
    applicable: list[str] = Field(
        default_factory=list, description="Engines capable of the class that ran on the host (the set E)"
    )
    silent: list[str] = Field(default_factory=list, description="Applicable engines that did not report it (E∖T)")


class PassiveFinding(BaseModel):
    """A single passive audit issue observed on one subdomain."""

    id: str = Field(description="Stable identifier derived from rule, subdomain, url and evidence")
    rule_id: str = Field(description="Check rule identifier, e.g. HDR-CSP-MISSING")
    title: str
    severity: Severity
    confidence: Confidence
    subdomain: str
    url: str
    description: str
    evidence: str = Field(default="", description="Raw observed artefact proving the issue")
    remediation: str
    cwe: str
    cwe_name: str = ""
    wstg: str | None = Field(default=None, description="OWASP WSTG v4.2 test identifier")
    owasp: list[str] = Field(default_factory=list, description="OWASP Top 10 (2025) category ids, e.g. A02:2025")
    cvss_vector: str | None = Field(default=None, description="None for tool alerts with no WAPTrix rule mapping")
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)
    sources: list[str] = Field(
        default_factory=lambda: ["waptrix"],
        description="Engines that observed this issue: 'waptrix' (built-in checks) and/or external tool names",
    )
    tool_refs: list[str] = Field(
        default_factory=list, description="Tool-native identifiers, e.g. zap:10038 or testssl:cert_trust"
    )
    correlation_score: float | None = Field(
        default=None, description="Cross-tool confidence C(f); None until the correlation engine runs"
    )
    correlation: CorrelationInfo | None = Field(default=None, description="Full voting breakdown for this finding")

    @staticmethod
    def make_id(rule_id: str, subdomain: str, url: str, evidence: str) -> str:
        digest = hashlib.sha256(f"{rule_id}|{subdomain}|{url}|{evidence}".encode()).hexdigest()
        return f"{rule_id}-{digest[:12]}"
