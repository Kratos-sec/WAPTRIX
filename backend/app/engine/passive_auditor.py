"""Stage scheduler: drives every in-scope subdomain through the six-stage workflow (S1–S6) concurrently.

See :mod:`app.engine.stages` for what each stage does and the run log it records.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol
from dataclasses import replace
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.checks import AuditContext, PassiveCheck, default_checks
from app.compliance.scorer import apply_scores, summarize
from app.engine.fetcher import Fetcher, FetchResult, TLSInspector
from app.engine.scope_guard import (
    RateLimiter,
    Resolver,
    ScopeError,
    Target,
    build_scope,
    resolve_and_check,
    system_resolver,
)
from app.engine.stages import RunLog, build_app_map, summarize_stages
from app.models.audit import (
    ApplicationMap,
    AuditRequest,
    AuditResult,
    AuditStatus,
    Endpoint,
    Stage,
    StageStatus,
    SubdomainResult,
    TLSInfo,
    ToolRunSummary,
)
from app.models.finding import PassiveFinding, Severity
from app.correlation import correlate, profiles
from app.tools.adapters import ACTIVE_ADAPTERS, PASSIVE_ADAPTERS, AdapterContext, AdapterResult, ToolAdapter

logger = logging.getLogger("waptrix.auditor")

ProgressCallback = Callable[[int, int, str], None]
TOOL_PARALLELISM = 2  # hosts one external tool may scan at the same time
MAX_RETEST_JOBS = 8  # tool runs per re-test round, per host
MAX_RETEST_PER_TOOL = 2  # of which at most this many per tool (keeps ZAP from being flooded)
STATIC_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js", ".woff", ".woff2", ".ttf", ".map")


class SupportsTLSInspect(Protocol):
    async def inspect(self, target: Target) -> TLSInfo: ...


class PassiveAuditor:
    def __init__(
        self,
        request: AuditRequest,
        transport: httpx.AsyncBaseTransport | None = None,
        tls_inspector: SupportsTLSInspect | None = None,
        resolver: Resolver = system_resolver,
        checks: list[PassiveCheck] | None = None,
        progress: ProgressCallback | None = None,
        adapters: list[ToolAdapter] | None = None,
        run_log: RunLog | None = None,
    ) -> None:
        self.request = request
        self.rate_limiter = RateLimiter(request.requests_per_second)
        self.transport = transport
        self.tls_inspector: SupportsTLSInspect = tls_inspector or TLSInspector(self.rate_limiter, timeout=request.timeout)
        self.resolver = resolver
        self.checks = checks if checks is not None else default_checks()
        self.progress = progress
        self.adapters = adapters if adapters is not None else self._build_adapters(request)
        self._tool_slots = {a.name: asyncio.Semaphore(TOOL_PARALLELISM) for a in self.adapters}
        self.run_log = run_log if run_log is not None else RunLog()
        # Every raw (pre-correlation) finding per host, including re-test rounds. Not serialised with the
        # result; the evaluation harness reads it to score each engine alone and the naive union.
        self.raw_findings: dict[str, list[PassiveFinding]] = {}

    @staticmethod
    def _build_adapters(request: AuditRequest) -> list[ToolAdapter]:
        adapters: list[ToolAdapter] = [PASSIVE_ADAPTERS[name]() for name in request.tools]
        if request.active:  # active adapters run only on explicit opt-in (enforced by AuditRequest)
            adapters += [ACTIVE_ADAPTERS[name]() for name in request.active_tools]
        return adapters

    async def run(self, audit_id: str | None = None) -> AuditResult:
        created = datetime.now(timezone.utc)
        request = self.request
        with self.run_log.stage(Stage.S1) as s1:
            decision = build_scope(
                request.subdomains,
                request.authorization_ref,
                scope_domains=request.scope_domains,
                allow_private=request.allow_private,
            )
            active = [a.name for a in self.adapters if _is_active(a)]
            s1.counts = {"targets": len(decision.targets), "rejected": len(decision.rejections)}
            s1.detail = (
                f"authorisation {request.authorization_ref.strip()}; budget {request.requests_per_second:g} req/s "
                f"per host, {request.concurrency} hosts in parallel, {request.tool_timeout:g}s per tool; "
                + (f"active mode ({', '.join(active)}) within {', '.join(request.scope_domains)}"
                   if active else "passive mode")
            )
        total = len(decision.targets)
        done = 0
        semaphore = asyncio.Semaphore(request.concurrency)

        async with Fetcher(self.rate_limiter, timeout=request.timeout, transport=self.transport,
                           cookie=request.cookie) as fetcher:

            async def bounded(target: Target) -> SubdomainResult:
                nonlocal done
                async with semaphore:
                    result = await self.audit_target(target, fetcher)
                done += 1
                if self.progress:
                    self.progress(done, total, target.display)
                return result

            results = list(await asyncio.gather(*(bounded(t) for t in decision.targets)))

        with self.run_log.stage(Stage.S6) as s6:
            summary = summarize(results)
            # Per-host S6 events already carry "findings"; summaries add counts across events, so the
            # engagement-wide event uses its own keys to avoid double-counting.
            s6.counts = {"retest": summary.total_retest, "reachable": summary.subdomains_reachable}
            s6.detail = f"overall grade {summary.grade}"

        events = list(self.run_log.events)
        return AuditResult(
            id=audit_id or uuid.uuid4().hex,
            authorization_ref=request.authorization_ref.strip(),
            status=AuditStatus.COMPLETED,
            created_at=created,
            completed_at=datetime.now(timezone.utc),
            request=request,
            subdomains=results,
            scope_rejections=decision.rejections,
            summary=summary,
            stages=summarize_stages(events),
            run_log=events,
        )

    async def audit_target(self, target: Target, fetcher: Fetcher) -> SubdomainResult:
        """Drive one host through S2–S6, looping S5→S3 for below-τ candidates (bounded)."""
        started = time.monotonic()
        host = target.display
        log = self.run_log
        result = SubdomainResult(subdomain=host, reachable=False, scanned_at=datetime.now(timezone.utc))
        raw: list[PassiveFinding] = []
        self.raw_findings[host] = raw

        with log.stage(Stage.S2, host) as s2:
            ctx, soup = await self._recon(target, fetcher, result, raw)
            s2.counts = {"findings": len(raw), "tools": len(result.tool_runs)}
            if ctx is None:
                s2.detail = result.error or "unreachable"

        if ctx is not None:
            page_url = ctx.url
            with log.stage(Stage.S3, host) as s3:
                seeds = [Endpoint(url=u, params=_params(u), source="seed") for u in self.request.seed_urls]
                ctx.app_map = result.app_map = build_app_map(target.host, page_url, soup, seeds)
                s3.counts = _map_counts(result.app_map)

            tried: set[tuple[str, str]] = set()
            with log.stage(Stage.S4, host) as s4:
                jobs = self._s4_jobs(ctx)
                if not jobs:
                    s4.skip("passive mode: no active engines selected")
                else:
                    s4.counts = await self._run_jobs(jobs, ctx, result, raw, Stage.S4, 0, tried)

            with log.stage(Stage.S5, host) as s5:
                s5.counts = self._correlate(result, raw)

            for round_no in range(1, self.request.retest_rounds + 1):
                if not result.retest_queue:
                    break
                jobs = self._retest_jobs(target, result, tried)
                if not jobs:
                    log.emit(Stage.S5, StageStatus.INFO, host, round=round_no,
                             detail=f"re-test loop closed: no untried engine/endpoint hypothesis for "
                                    f"{len(result.retest_queue)} queued candidate(s)")
                    break
                with log.stage(Stage.S3, host, round=round_no, detail="re-test: refined endpoint hypotheses") as s3:
                    extra = [Endpoint(url=url, params=_params(url), source="retest") for _, url in jobs]
                    previous = result.app_map.endpoints if result.app_map else []  # keeps seeds
                    ctx.app_map = result.app_map = build_app_map(
                        target.host, page_url, soup, [*previous, *extra])
                    s3.counts = _map_counts(result.app_map)
                with log.stage(Stage.S4, host, round=round_no) as s4:
                    s4.counts = await self._run_jobs(jobs, ctx, result, raw, Stage.S4, round_no, tried)
                with log.stage(Stage.S5, host, round=round_no) as s5:
                    s5.counts = self._correlate(result, raw)
                result.retest_rounds_run = round_no

        with log.stage(Stage.S6, host) as s6:
            self._finish(result, started)
            s6.counts = {"findings": len(result.findings)}
            s6.detail = f"score {result.score if result.score is not None else 'n/a'}, grade {result.grade}"
        return result

    async def _recon(self, target: Target, fetcher: Fetcher, result: SubdomainResult,
                     raw: list[PassiveFinding]) -> tuple[AdapterContext | None, BeautifulSoup | None]:
        """Stage S2: resolve, observe with read-only GETs and TLS, run built-in checks and passive tools.

        Returns the adapter context and parsed page for later stages; the context is None when the host
        cannot be assessed.
        """
        try:
            result.ip_addresses = await resolve_and_check(target.host, self.request.allow_private, self.resolver)
        except ScopeError as exc:
            result.error = f"scope guard: {exc}"
            return None, None
        except OSError as exc:
            result.error = f"DNS resolution failed: {exc}"
            return None, None

        https_res, http_res, tls_info = await asyncio.gather(
            fetcher.get(target.https_url("/"), target),
            fetcher.get(target.http_url("/"), target),
            self._inspect_tls(target),
        )

        ctx = AuditContext(target=target, https=https_res, http=http_res, tls=tls_info)
        primary = ctx.primary
        if primary is not None and self.request.include_metadata:
            base = target.https_url if primary is https_res else target.http_url
            ctx.robots, ctx.security_txt = await asyncio.gather(
                fetcher.get(base("/robots.txt"), target),
                fetcher.get(base("/.well-known/security.txt"), target),
            )

        result.https = https_res.to_observation()
        result.http = http_res.to_observation()
        result.tls = tls_info
        result.reachable = primary is not None
        if primary is None:
            result.error = f"unreachable: https={https_res.error or https_res.status_code}; http={http_res.error or http_res.status_code}"
            return None, None

        result.scheme = "https" if primary is https_res else "http"
        result.status_code = primary.status_code
        result.final_url = primary.final_url
        if ctx.http_ok:
            result.https_redirect = _redirects_to_https(http_res)

        errors: list[str] = []
        for check in self.checks:
            try:
                raw.extend(check.run(ctx))
            except Exception as exc:  # a faulty rule must never abort the whole audit
                logger.exception("check %s failed on %s", check.name, target.display)
                errors.append(f"{check.name}: {exc}")
        if errors:
            result.error = "check errors: " + "; ".join(errors)

        actx = self._adapter_context(ctx, result, fetcher)
        passive = [(a, actx.url) for a in self.adapters if not _is_active(a)]
        if passive:
            await self._run_jobs(passive, actx, result, raw, Stage.S2, 0, set())
        return actx, ctx.soup

    def _adapter_context(self, ctx: AuditContext, result: SubdomainResult, fetcher: Fetcher) -> AdapterContext:
        target = ctx.target
        page_url = result.final_url or target.https_url()

        async def fetch(url: str) -> bytes | None:
            res = await fetcher.get(url, target)
            return res.body.encode("utf-8") if res.ok and res.status_code == 200 else None

        scripts: list[str] = []
        if ctx.soup is not None:
            for tag in ctx.soup.find_all("script", src=True):
                url = urljoin(page_url, str(tag["src"]).strip())
                if urlsplit(url).hostname == target.host and url not in scripts:
                    scripts.append(url)
        return AdapterContext(target=target, url=page_url, https_ok=ctx.https_ok, script_urls=scripts,
                              fetch=fetch, timeout=self.request.tool_timeout, cookie=self.request.cookie)

    def _s4_jobs(self, ctx: AdapterContext) -> list[tuple[ToolAdapter, str]]:
        """Stage S4: resolve active engines onto the S3 map. Per-endpoint engines get each parameterised
        endpoint (capped by max_endpoints); the rest run once from the page."""
        endpoints = [e.url for e in (ctx.app_map.parameterised() if ctx.app_map else [])]
        jobs: list[tuple[ToolAdapter, str]] = []
        for adapter in self.adapters:
            if not _is_active(adapter):
                continue
            if adapter.per_endpoint:
                jobs += [(adapter, url) for url in (endpoints[: self.request.max_endpoints] or [ctx.url])]
            else:
                jobs.append((adapter, ctx.url))
        return jobs

    def _retest_jobs(self, target: Target, result: SubdomainResult,
                     tried: set[tuple[str, str]]) -> list[tuple[ToolAdapter, str]]:
        """Refined hypotheses for queued candidates: aim each active engine capable of (or confirming) the
        candidate's class at the candidate's exact endpoint, unless that pair has already been tried."""
        jobs: list[tuple[ToolAdapter, str]] = []
        planned: set[tuple[str, str]] = set()
        per_tool: dict[str, int] = {}
        queue = sorted(result.retest_queue, key=lambda f: -f.severity.rank)
        for finding in queue:
            if len(jobs) >= MAX_RETEST_JOBS:
                break
            path = urlsplit(finding.url).path.lower()
            if (urlsplit(finding.url).hostname != target.host or finding.severity == Severity.INFO
                    or path.endswith(STATIC_SUFFIXES)):
                continue
            tag = profiles.tag_for(finding.rule_id, finding.cwe or None)
            for adapter in self.adapters:
                if not _is_active(adapter):
                    continue
                if not (profiles.confirms(adapter.name, tag) or tag in profiles.detects(adapter.name)):
                    continue
                key = (adapter.name, finding.url)
                if key in tried or key in planned or per_tool.get(adapter.name, 0) >= MAX_RETEST_PER_TOOL:
                    continue
                if len(jobs) >= MAX_RETEST_JOBS:
                    break
                planned.add(key)
                per_tool[adapter.name] = per_tool.get(adapter.name, 0) + 1
                jobs.append((adapter, finding.url))
        return jobs

    async def _run_jobs(self, jobs: list[tuple[ToolAdapter, str]], base: AdapterContext, result: SubdomainResult,
                        raw: list[PassiveFinding], stage: Stage, round_no: int,
                        tried: set[tuple[str, str]]) -> dict[str, int]:
        target = base.target

        async def one(adapter: ToolAdapter, url: str) -> AdapterResult:
            tried.add((adapter.name, url))
            async with self._tool_slots[adapter.name]:
                try:
                    return await adapter.run(replace(base, url=url))
                except Exception as exc:  # a broken tool must not abort the audit
                    logger.exception("tool %s failed on %s", adapter.name, target.display)
                    return AdapterResult(tool=adapter.name,
                                         run=ToolRunSummary(tool=adapter.name, error=f"adapter error: {exc}"))

        outcomes = await asyncio.gather(*(one(a, url) for a, url in jobs))
        new = 0
        for (_, url), outcome in zip(jobs, outcomes):
            # Keep raw findings; de-duplication and cross-tool voting happen in S5.
            raw.extend(outcome.findings)
            new += len(outcome.findings)
            result.technologies.extend(outcome.technologies)
            run = outcome.run or ToolRunSummary(tool=outcome.tool, finding_count=len(outcome.findings))
            run.stage, run.target_url, run.round = stage.value, url, round_no
            result.tool_runs.append(run)
        return {"runs": len(jobs), "findings": new}

    def _correlate(self, result: SubdomainResult, raw: list[PassiveFinding]) -> dict[str, int]:
        """Stage S5: vote across every engine that ran, admitting findings at or above τ and queuing the rest.

        Correlation merges corroborating engines onto a representative in place, so it runs on copies: the
        raw set must stay untouched for the next re-test round to re-vote from scratch.
        """
        engines_ran = {"waptrix"} | {run.tool for run in result.tool_runs if run.succeeded}
        outcome = correlate([f.model_copy(deep=True) for f in raw], engines_ran)
        result.findings = outcome.admitted
        result.retest_queue = outcome.queued
        return {"raw": len(raw), "admitted": len(outcome.admitted), "queued": len(outcome.queued),
                "confirmed": sum(1 for f in outcome.admitted if f.correlation and f.correlation.confirmed)}

    async def _inspect_tls(self, target: Target) -> TLSInfo:
        try:
            return await self.tls_inspector.inspect(target)
        except Exception as exc:  # defensive: inspector failures become observations, not crashes
            logger.warning("TLS inspection failed for %s: %s", target.display, exc)
            return TLSInfo(host=target.host, port=target.tls_port, error=f"TLS inspection failed: {exc}")

    @staticmethod
    def _finish(result: SubdomainResult, started: float) -> SubdomainResult:
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return apply_scores(result)


def _is_active(adapter: ToolAdapter) -> bool:
    return adapter.name in ACTIVE_ADAPTERS


def _params(url: str) -> list[str]:
    return sorted({key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def _map_counts(app_map: ApplicationMap) -> dict[str, int]:
    return {"endpoints": len(app_map.endpoints), "parameterised": len(app_map.parameterised()),
            "parameters": len(app_map.parameters)}


def _redirects_to_https(http_res: FetchResult) -> bool:
    final = http_res.final_url or ""
    return final.startswith("https://") or (http_res.stopped_offscope or "").startswith("https://")


async def run_audit(request: AuditRequest, **kwargs) -> AuditResult:
    """Convenience wrapper: validate scope and run a full passive audit."""
    return await PassiveAuditor(request, **kwargs).run()


__all__ = ["PassiveAuditor", "run_audit", "ScopeError"]
