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
    cvss_vector: str
    cvss_score: float
    references: list[str] = Field(default_factory=list)

    @staticmethod
    def make_id(rule_id: str, subdomain: str, url: str, evidence: str) -> str:
        digest = hashlib.sha256(f"{rule_id}|{subdomain}|{url}|{evidence}".encode()).hexdigest()
        return f"{rule_id}-{digest[:12]}"
