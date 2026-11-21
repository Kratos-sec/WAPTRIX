"""Orchestrates passive observation and all checks for every in-scope subdomain concurrently."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol

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
from app.models.audit import AuditRequest, AuditResult, AuditStatus, SubdomainResult, TLSInfo

logger = logging.getLogger("waptrix.auditor")

ProgressCallback = Callable[[int, int, str], None]


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
    ) -> None:
        self.request = request
        self.rate_limiter = RateLimiter(request.requests_per_second)
        self.transport = transport
        self.tls_inspector: SupportsTLSInspect = tls_inspector or TLSInspector(self.rate_limiter, timeout=request.timeout)
        self.resolver = resolver
        self.checks = checks if checks is not None else default_checks()
        self.progress = progress

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
        return self._finish(result, started)

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
