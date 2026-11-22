"""Common interface for external tool adapters (passive and active).

An adapter turns one tool invocation against one subdomain into WAPTrix findings. Where a tool reports
the same issue as a built-in rule, the adapter emits that rule ID, so scoring, CVSS and remediation stay
consistent. Anything else becomes a tool-specific finding (`<TOOL>-<id>`) carrying the tool's own
severity and CWE, with no CVSS score.
"""

from __future__ import annotations

import json
import re
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from app.checks.base import rule_finding, truncate
from app.compliance import normalize_cwe, owasp_for_cwe
from app.engine.scope_guard import Target
from app.models.audit import ApplicationMap, Technology, ToolRunSummary
from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.runner import ToolRun, run_tool

STDERR_TAIL = 2000

# Fetch a same-host URL through WAPTrix's rate-limited, size-capped fetcher. Returns the body or None.
FetchBody = Callable[[str], Awaitable[bytes | None]]


@dataclass
class AdapterContext:
    target: Target
    url: str  # endpoint to test: the primary page, or an S3 map / re-test endpoint for per-endpoint engines
    https_ok: bool
    script_urls: list[str] = field(default_factory=list)  # same-host <script src> URLs on that page
    fetch: FetchBody | None = None
    timeout: float = 300.0
    app_map: ApplicationMap | None = None  # Stage S3 artefact, available to S4 engines
    cookie: str | None = None  # session cookie to send, when the audit supplies one

    @property
    def subdomain(self) -> str:
        return self.target.display


@dataclass
class AdapterResult:
    tool: str
    findings: list[PassiveFinding] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    run: ToolRunSummary | None = None


class ToolAdapter(ABC):
    name: ClassVar[str]
    default_timeout: ClassVar[float] = 300.0
    # True for engines that test one endpoint's parameters (sqlmap): S4 runs them once per parameterised
    # endpoint of the S3 map, and the re-test loop aims them at a below-τ candidate's exact endpoint.
    per_endpoint: ClassVar[bool] = False

    def applicable(self, ctx: AdapterContext) -> str | None:
        """Return a reason to skip this host, or None to run."""
        return None

    @abstractmethod
    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult: ...

    async def run(self, ctx: AdapterContext) -> AdapterResult:
        skip = self.applicable(ctx)
        if skip:
            return AdapterResult(tool=self.name, run=ToolRunSummary(tool=self.name, error=f"skipped: {skip}"))
        with tempfile.TemporaryDirectory(prefix=f"waptrix-{self.name}-") as tmp:
            return await self.execute(ctx, Path(tmp))

    # ------------------------------------------------------------------ helpers

    def mapped(self, ctx: AdapterContext, rule_id: str, ref: str, evidence: str, detail: str | None = None,
               url: str | None = None) -> PassiveFinding:
        return rule_finding(rule_id, ctx.subdomain, url or ctx.url, evidence, detail,
                            sources=[self.name], tool_refs=[f"{self.name}:{ref}"])

    def unmapped(
        self,
        ctx: AdapterContext,
        ref: str,
        title: str,
        severity: Severity,
        confidence: Confidence,
        cwe: str | int | None,
        description: str,
        evidence: str,
        remediation: str = "",
        references: list[str] | None = None,
        url: str | None = None,
    ) -> PassiveFinding:
        rule_id = f"{self.name.upper()}-{re.sub(r'[^A-Za-z0-9]+', '-', ref).strip('-').upper()}"
        cwe_id = normalize_cwe(cwe)
        location = url or ctx.url
        evidence = truncate(evidence)
        return PassiveFinding(
            id=PassiveFinding.make_id(rule_id, ctx.subdomain, location, evidence),
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=confidence,
            subdomain=ctx.subdomain,
            url=location,
            description=description or title,
            evidence=evidence,
            remediation=remediation or "See the tool documentation and references for remediation guidance.",
            cwe=cwe_id or "",
            owasp=owasp_for_cwe(cwe_id),
            references=references or [],
            sources=[self.name],
            tool_refs=[f"{self.name}:{ref}"],
        )

    async def invoke(self, argv: list[str], ctx: AdapterContext, timeout: float | None = None) -> ToolRun:
        return await run_tool(self.name, argv, timeout=timeout or min(ctx.timeout, self.default_timeout))


def summarize_run(run: ToolRun, finding_count: int, error: str | None = None) -> ToolRunSummary:
    return ToolRunSummary(
        tool=run.tool,
        argv=run.argv,
        started_at=run.started_at,
        duration_s=run.duration_s,
        exit_code=run.exit_code,
        timed_out=run.timed_out,
        error=error or run.error or ("timed out" if run.timed_out else None),
        finding_count=finding_count,
        stderr_tail=run.stderr[-STDERR_TAIL:],
    )


def read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def utc(ts: str) -> datetime:
    value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
