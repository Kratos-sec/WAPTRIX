"""Abstract passive check interface and the shared per-subdomain audit context."""

from __future__ import annotations

import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from typing import ClassVar

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from app.compliance import get_rule
from app.compliance.scorer import cvss31_base_score
from app.engine.fetcher import FetchResult
from app.engine.scope_guard import Target
from app.models.audit import TLSInfo
from app.models.finding import Confidence, PassiveFinding, Severity

MAX_EVIDENCE_CHARS = 600

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


@dataclass
class AuditContext:
    """Everything passively observed for one subdomain. Checks must only read from this."""

    target: Target
    https: FetchResult | None = None
    http: FetchResult | None = None
    tls: TLSInfo | None = None
    robots: FetchResult | None = None
    security_txt: FetchResult | None = None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def subdomain(self) -> str:
        return self.target.display

    @property
    def https_ok(self) -> bool:
        return bool(self.https and self.https.ok)

    @property
    def http_ok(self) -> bool:
        return bool(self.http and self.http.ok)

    @property
    def primary(self) -> FetchResult | None:
        """The response used for content analysis: HTTPS when available, else plain HTTP."""
        if self.https_ok:
            return self.https
        if self.http_ok:
            return self.http
        return None

    @property
    def primary_is_https(self) -> bool:
        primary = self.primary
        return bool(primary and (primary.final_url or "").startswith("https://"))

    @cached_property
    def soup(self) -> BeautifulSoup | None:
        primary = self.primary
        if primary is None or not primary.body or not primary.is_html:
            return None
        return BeautifulSoup(primary.body, "html.parser")

    def responses(self) -> list[FetchResult]:
        return [r for r in (self.https, self.http) if r is not None and r.ok]


def truncate(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


class PassiveCheck(ABC):
    """A Burp-style passive audit rule group. Implementations must never issue network requests."""

    name: ClassVar[str]
    rule_ids: ClassVar[tuple[str, ...]]

    @abstractmethod
    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        """Inspect the context and return findings."""

    def finding(
        self,
        ctx: AuditContext,
        rule_id: str,
        evidence: str,
        url: str | None = None,
        detail: str | None = None,
    ) -> PassiveFinding:
        if rule_id not in self.rule_ids:
            raise ValueError(f"{self.name} emitted undeclared rule {rule_id}")
        rule = get_rule(rule_id)
        location = url or (ctx.primary.final_url if ctx.primary else None) or ctx.target.https_url()
        evidence = truncate(evidence)
        description = rule["description"] if not detail else f"{rule['description']}\n\n{detail}"
        return PassiveFinding(
            id=PassiveFinding.make_id(rule_id, ctx.subdomain, location, evidence),
            rule_id=rule_id,
            title=rule["title"],
            severity=Severity(rule["severity"]),
            confidence=Confidence(rule["confidence"]),
            subdomain=ctx.subdomain,
            url=location,
            description=description,
            evidence=evidence,
            remediation=rule["remediation"],
            cwe=rule["cwe"],
            cwe_name=rule.get("cwe_name", ""),
            wstg=rule.get("wstg"),
            owasp=list(rule["owasp"]),
            cvss_vector=rule["cvss_vector"],
            cvss_score=cvss31_base_score(rule["cvss_vector"]),
            references=list(rule.get("references", [])),
        )
