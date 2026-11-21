"""Orchestrates passive observation and all checks for every in-scope subdomain concurrently."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import httpx

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
from app.models.audit import AuditRequest, AuditResult, AuditStatus, SubdomainResult, TLSInfo, ToolRunSummary
from app.tools.adapters import ACTIVE_ADAPTERS, PASSIVE_ADAPTERS, AdapterContext, AdapterResult, ToolAdapter
from app.tools.merge import merge_findings

logger = logging.getLogger("waptrix.auditor")

ProgressCallback = Callable[[int, int, str], None]
TOOL_PARALLELISM = 2  # hosts one external tool may scan at the same time


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

    @staticmethod
    def _build_adapters(request: AuditRequest) -> list[ToolAdapter]:
        adapters: list[ToolAdapter] = [PASSIVE_ADAPTERS[name]() for name in request.tools]
        if request.active:  # active adapters run only on explicit opt-in (enforced by AuditRequest)
            adapters += [ACTIVE_ADAPTERS[name]() for name in request.active_tools]
        return adapters

    async def run(self, audit_id: str | None = None) -> AuditResult:
        created = datetime.now(timezone.utc)
        decision = build_scope(
            self.request.subdomains,
            self.request.authorization_ref,
            scope_domains=self.request.scope_domains,
            allow_private=self.request.allow_private,
        )
        total = len(decision.targets)
        done = 0
        semaphore = asyncio.Semaphore(self.request.concurrency)

        async with Fetcher(self.rate_limiter, timeout=self.request.timeout, transport=self.transport) as fetcher:

            async def bounded(target: Target) -> SubdomainResult:
                nonlocal done
                async with semaphore:
                    result = await self.audit_target(target, fetcher)
                done += 1
                if self.progress:
                    self.progress(done, total, target.display)
                return result

            results = await asyncio.gather(*(bounded(t) for t in decision.targets))

        return AuditResult(
            id=audit_id or uuid.uuid4().hex,
            authorization_ref=self.request.authorization_ref.strip(),
            status=AuditStatus.COMPLETED,
            created_at=created,
            completed_at=datetime.now(timezone.utc),
            request=self.request,
            subdomains=list(results),
            scope_rejections=decision.rejections,
            summary=summarize(list(results)),
        )

    async def audit_target(self, target: Target, fetcher: Fetcher) -> SubdomainResult:
        started = time.monotonic()
        scanned_at = datetime.now(timezone.utc)
        result = SubdomainResult(subdomain=target.display, reachable=False, scanned_at=scanned_at)

        try:
            result.ip_addresses = await resolve_and_check(target.host, self.request.allow_private, self.resolver)
        except ScopeError as exc:
            result.error = f"scope guard: {exc}"
            return self._finish(result, started)
        except OSError as exc:
            result.error = f"DNS resolution failed: {exc}"
            return self._finish(result, started)

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
            return self._finish(result, started)

        result.scheme = "https" if primary is https_res else "http"
        result.status_code = primary.status_code
        result.final_url = primary.final_url
        if ctx.http_ok:
            result.https_redirect = _redirects_to_https(http_res)

        errors: list[str] = []
        for check in self.checks:
            try:
                result.findings.extend(check.run(ctx))
            except Exception as exc:  # a faulty rule must never abort the whole audit
                logger.exception("check %s failed on %s", check.name, target.display)
                errors.append(f"{check.name}: {exc}")
        if errors:
            result.error = "check errors: " + "; ".join(errors)
        if self.adapters:
            await self._run_tools(ctx, result, fetcher)
        return self._finish(result, started)

    async def _run_tools(self, ctx: AuditContext, result: SubdomainResult, fetcher: Fetcher) -> None:
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
        actx = AdapterContext(target=target, url=page_url, https_ok=ctx.https_ok, script_urls=scripts,
                              fetch=fetch, timeout=self.request.tool_timeout)

        async def one(adapter: ToolAdapter) -> AdapterResult:
            async with self._tool_slots[adapter.name]:
                try:
                    return await adapter.run(actx)
                except Exception as exc:  # a broken tool must not abort the audit
                    logger.exception("tool %s failed on %s", adapter.name, target.display)
                    return AdapterResult(tool=adapter.name, run=ToolRunSummary(tool=adapter.name, error=f"adapter error: {exc}"))

        for outcome in await asyncio.gather(*(one(a) for a in self.adapters)):
            result.findings = merge_findings(result.findings, outcome.findings)
            result.technologies.extend(outcome.technologies)
            result.tool_runs.append(
                outcome.run or ToolRunSummary(tool=outcome.tool, finding_count=len(outcome.findings))
            )

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


def _redirects_to_https(http_res: FetchResult) -> bool:
    final = http_res.final_url or ""
    return final.startswith("https://") or (http_res.stopped_offscope or "").startswith("https://")


async def run_audit(request: AuditRequest, **kwargs) -> AuditResult:
    """Convenience wrapper: validate scope and run a full passive audit."""
    return await PassiveAuditor(request, **kwargs).run()


__all__ = ["PassiveAuditor", "run_audit", "ScopeError"]
