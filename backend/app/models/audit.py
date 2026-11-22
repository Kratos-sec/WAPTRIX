"""Audit request / result schemas."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.finding import PassiveFinding, Severity

ENGINE_VERSION = "1.0.0"


class AuditRequest(BaseModel):
    """Input for a passive audit engagement."""

    subdomains: list[str] = Field(min_length=1, description="Hostnames to audit (scheme/path are stripped)")
    authorization_ref: str = Field(
        description="Engagement / ticket reference proving written authorization, e.g. ENG-2026-001"
    )
    scope_domains: list[str] = Field(
        default_factory=list,
        description="Optional apex domains; subdomains outside these are rejected",
    )
    concurrency: int = Field(default=5, ge=1, le=20, description="Subdomains audited in parallel")
    requests_per_second: float = Field(default=2.0, gt=0, le=10, description="Per-host request rate cap")
    timeout: float = Field(default=10.0, ge=1, le=60, description="Per-request timeout in seconds")
    allow_private: bool = Field(default=False, description="Permit targets resolving to private/loopback IPs")
    include_metadata: bool = Field(default=True, description="Fetch /robots.txt and /.well-known/security.txt")
    tool_timeout: float = Field(default=600.0, ge=10, le=3600, description="Per-tool, per-host time limit in seconds")
    tools: list[str] = Field(
        default_factory=list,
        description="External passive tools to run in addition to the built-in checks (see GET /api/tools)",
    )
    active: bool = Field(
        default=False,
        description="Opt in to active scanning. Required before any active tool runs; also needs scope_domains set.",
    )
    active_tools: list[str] = Field(
        default_factory=list,
        description="Active tools (nmap, nuclei, nikto, wapiti, sqlmap) that send probes or payloads; "
        "ignored unless active=true and scope_domains is non-empty",
    )
    cookie: str | None = Field(
        default=None, max_length=4096,
        description="Session cookie header value (e.g. 'PHPSESSID=abc; security=low') sent by the built-in "
        "fetcher and by tools that accept one, so authenticated pages can be scanned",
    )
    seed_urls: list[str] = Field(
        default_factory=list, max_length=100,
        description="Extra same-host URLs (with parameters) added to the S3 application map, so engines "
        "test endpoints the start page does not link to",
    )
    retest_rounds: int = Field(
        default=1, ge=0, le=3,
        description="Bounded S5→S3 re-test loop: rounds in which below-τ candidates are re-probed by active "
        "engines at their exact endpoint (0 disables the loop)",
    )
    max_endpoints: int = Field(
        default=5, ge=1, le=50,
        description="Per host, how many parameterised endpoints from the S3 application map per-endpoint "
        "active engines (sqlmap) may target",
    )

    @field_validator("subdomains")
    @classmethod
    def _non_blank(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("at least one subdomain is required")
        return cleaned

    @field_validator("tools")
    @classmethod
    def _known_passive_tools(cls, value: list[str]) -> list[str]:
        from app.tools.adapters import PASSIVE_ADAPTERS

        wanted = list(dict.fromkeys(t.strip().lower() for t in value if t and t.strip()))
        unknown = [t for t in wanted if t not in PASSIVE_ADAPTERS]
        if unknown:
            raise ValueError(
                f"unknown or non-passive tool(s): {', '.join(unknown)}; passive tools: {', '.join(PASSIVE_ADAPTERS)}"
            )
        return wanted

    @field_validator("active_tools")
    @classmethod
    def _known_active_tools(cls, value: list[str]) -> list[str]:
        from app.tools.adapters import ACTIVE_ADAPTERS

        wanted = list(dict.fromkeys(t.strip().lower() for t in value if t and t.strip()))
        unknown = [t for t in wanted if t not in ACTIVE_ADAPTERS]
        if unknown:
            raise ValueError(
                f"unknown or non-active tool(s): {', '.join(unknown)}; active tools: {', '.join(ACTIVE_ADAPTERS)}"
            )
        return wanted

    @model_validator(mode="after")
    def _gate_active_mode(self) -> "AuditRequest":
        """Active tools need an explicit opt-in and a declared scope; auth ref is already required."""
        if self.active_tools:
            if not self.active:
                raise ValueError("active_tools requires active=true (explicit opt-in to active scanning)")
            if not self.scope_domains:
                raise ValueError("active scanning requires scope_domains to bound the engagement")
        return self


class RedirectHop(BaseModel):
    url: str
    status_code: int
    location: str | None = None


class HttpObservation(BaseModel):
    """Serializable summary of one read-only GET exchange."""

    url: str
    final_url: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    elapsed_ms: int = 0
    body_bytes: int = 0
    error: str | None = None


class TLSInfo(BaseModel):
    host: str
    port: int = 443
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_serial: str | None = None
    cert_not_before: datetime | None = None
    cert_not_after: datetime | None = None
    days_to_expiry: int | None = None
    san: list[str] = Field(default_factory=list)
    self_signed: bool = False
    hostname_match: bool | None = None
    trusted: bool | None = None
    verify_error: str | None = None
    legacy_protocols_accepted: list[str] = Field(default_factory=list)
    legacy_probe: str = Field(default="not_run", description="not_run | completed | unsupported_by_client")
    error: str | None = None


class ToolRunSummary(BaseModel):
    """What one external tool did against one subdomain (raw output is not stored here)."""

    tool: str
    stage: str | None = Field(default=None, description="Workflow stage the run belonged to (S2 or S4)")
    target_url: str | None = Field(default=None, description="Endpoint the run targeted")
    round: int = Field(default=0, description="Re-test round; 0 is the first pass")
    argv: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    duration_s: float = 0.0
    exit_code: int | None = None
    timed_out: bool = False
    error: str | None = None
    finding_count: int = 0
    stderr_tail: str = ""

    @property
    def succeeded(self) -> bool:
        """True when the tool actually scanned: not skipped, not broken. Only these count as engines that ran."""
        if self.finding_count > 0:
            return True
        return not self.error and not self.timed_out and self.exit_code in (0, None)


class Technology(BaseModel):
    name: str
    version: str | None = None
    source: str


class CategoryStatus(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    MANUAL_REVIEW = "manual_review"


class CategoryResult(BaseModel):
    id: str
    name: str
    status: CategoryStatus
    coverage: str
    finding_count: int = 0
    max_severity: Severity | None = None
    rule_ids: list[str] = Field(default_factory=list)
    pass_rate: float | None = Field(default=None, description="Share of audited subdomains passing (aggregate only)")


class Stage(str, Enum):
    """The six-stage assessment workflow (paper Section III-C, Fig. 3)."""

    S1 = "S1"  # scope & authorisation
    S2 = "S2"  # passive reconnaissance
    S3 = "S3"  # application map
    S4 = "S4"  # phase controllers / active engines
    S5 = "S5"  # correlation, scoring and confirmation
    S6 = "S6"  # risk assignment & report

    @property
    def label(self) -> str:
        return STAGE_TITLES[self]


STAGE_TITLES = {
    Stage.S1: "Scope & authorisation",
    Stage.S2: "Passive reconnaissance",
    Stage.S3: "Application map",
    Stage.S4: "Phase controllers",
    Stage.S5: "Correlation & confirmation",
    Stage.S6: "Risk & report",
}


class StageStatus(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    INFO = "info"


class RunEvent(BaseModel):
    """One entry of the run log: a stage starting, finishing or reporting progress, per host or global."""

    seq: int
    at: datetime
    stage: Stage
    status: StageStatus
    subdomain: str | None = Field(default=None, description="None for engagement-wide events (S1, final S6)")
    round: int = Field(default=0, description="Re-test round; 0 is the first pass")
    detail: str = ""
    counts: dict[str, int] = Field(default_factory=dict)
    duration_ms: int | None = None


class StageSummary(BaseModel):
    """Aggregate of one stage across every host of the run."""

    stage: Stage
    name: str
    status: StageStatus
    hosts: int = 0
    runs: int = Field(default=0, description="Times the stage completed (re-test rounds re-enter S3–S5)")
    duration_ms: int = Field(default=0, description="Summed wall time of every completed run of the stage")
    counts: dict[str, int] = Field(default_factory=dict)


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    source: str = Field(description="link | form | script | page | retest")


class ApplicationMap(BaseModel):
    """Stage S3 artefact: URL tree and parameter inventory of the host, built from observed content."""

    endpoints: list[Endpoint] = Field(default_factory=list)
    truncated: bool = False

    @property
    def parameters(self) -> list[str]:
        return sorted({p for e in self.endpoints for p in e.params})

    def parameterised(self, method: str = "GET") -> list[Endpoint]:
        return [e for e in self.endpoints if e.params and e.method == method]


class SubdomainResult(BaseModel):
    subdomain: str
    reachable: bool
    scheme: str | None = None
    status_code: int | None = None
    final_url: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    https_redirect: bool | None = None
    https: HttpObservation | None = None
    http: HttpObservation | None = None
    tls: TLSInfo | None = None
    findings: list[PassiveFinding] = Field(default_factory=list)
    retest_queue: list[PassiveFinding] = Field(
        default_factory=list,
        description="Candidates with C(f) < τ, held for Stage S3 re-test rather than discarded",
    )
    technologies: list[Technology] = Field(default_factory=list)
    tool_runs: list[ToolRunSummary] = Field(default_factory=list)
    app_map: ApplicationMap | None = Field(default=None, description="Stage S3 application map")
    retest_rounds_run: int = Field(default=0, description="S5→S3 re-test rounds actually executed")
    score: int | None = None
    grade: str = "N/A"
    categories: list[CategoryResult] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    error: str | None = None
    scanned_at: datetime | None = None
    duration_ms: int = 0


class ScopeRejection(BaseModel):
    input: str
    reason: str


class ComplianceSummary(BaseModel):
    overall_score: int | None = None
    grade: str = "N/A"
    subdomains_total: int = 0
    subdomains_reachable: int = 0
    total_findings: int = 0
    total_retest: int = Field(default=0, description="Candidates below τ awaiting re-test across all hosts")
    severity_counts: dict[str, int] = Field(default_factory=dict)
    grade_distribution: dict[str, int] = Field(default_factory=dict)
    categories: list[CategoryResult] = Field(default_factory=list)
    top_rules: list[dict] = Field(default_factory=list)


class AuditStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditResult(BaseModel):
    id: str
    authorization_ref: str
    status: AuditStatus = AuditStatus.COMPLETED
    created_at: datetime
    completed_at: datetime | None = None
    engine_version: str = ENGINE_VERSION
    request: AuditRequest | None = None
    subdomains: list[SubdomainResult] = Field(default_factory=list)
    scope_rejections: list[ScopeRejection] = Field(default_factory=list)
    summary: ComplianceSummary = Field(default_factory=ComplianceSummary)
    stages: list[StageSummary] = Field(default_factory=list)
    run_log: list[RunEvent] = Field(default_factory=list)
    error: str | None = None
    demo: bool = False

    def for_subdomain(self, subdomain: str) -> "AuditResult":
        """Return a copy of this audit restricted to a single subdomain (for scoped exports)."""
        from app.compliance.scorer import summarize

        wanted = subdomain.strip().lower()
        selected = [s for s in self.subdomains if s.subdomain == wanted]
        if not selected:
            raise KeyError(subdomain)
        return self.model_copy(
            update={"subdomains": selected, "scope_rejections": [], "summary": summarize(selected)}
        )


class AuditListItem(BaseModel):
    id: str
    authorization_ref: str
    status: AuditStatus
    created_at: datetime
    completed_at: datetime | None = None
    overall_score: int | None = None
    grade: str = "N/A"
    subdomains_total: int = 0
    total_findings: int = 0
    demo: bool = False
