"""OWASP ZAP passive scanning via the daemon's REST API.

Passive mode: ZAP fetches the page URL once (no spider, no redirects followed), its passive rules run on
that response, and the alerts are collected. The site node is then removed so that results never leak
between audits. The API key travels in the X-ZAP-API-Key header, never in a URL, so it cannot end up in
error messages or stored audit records.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.models.audit import ToolRunSummary
from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter
from app.tools.registry import zap_settings

# ZAP passive rule (pluginId) -> built-in rule reporting the same issue.
PLUGIN_RULES = {
    "10038": "HDR-CSP-MISSING",
    "10055": "HDR-CSP-WEAK",
    "10035": "HDR-HSTS-MISSING",
    "10020": "HDR-XFO-MISSING",
    "10021": "HDR-XCTO-MISSING",
    "10063": "HDR-PERMISSIONS-MISSING",
    "10010": "CKE-NO-HTTPONLY",
    "10011": "CKE-NO-SECURE",
    "10054": "CKE-NO-SAMESITE",
    "10036": "DISC-SERVER-VERSION",
    "10037": "DISC-VERSION-HEADER",
    "10027": "DISC-HTML-COMMENTS",
    "10202": "FORM-NO-CSRF-TOKEN",
    "10003": "JS-VULNERABLE-LIBRARY",
}
RISK = {"High": Severity.HIGH, "Medium": Severity.MEDIUM, "Low": Severity.LOW, "Informational": Severity.INFO}
CONFIDENCE = {"Confirmed": Confidence.CERTAIN, "High": Confidence.FIRM, "Medium": Confidence.FIRM,
              "Low": Confidence.TENTATIVE, "False Positive": Confidence.TENTATIVE}
PSCAN_WAIT = 60.0


def parse(alerts: list[dict[str, Any]], ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for alert in alerts:
        plugin, evidence, url = str(alert.get("pluginId", "")), alert.get("evidence", ""), alert.get("url") or ctx.url
        if alert.get("confidence") == "False Positive" or (plugin, evidence, url) in seen:
            continue
        seen.add((plugin, evidence, url))
        cwe = int(alert.get("cweid") or 0)
        risk = RISK.get(alert.get("risk", ""), Severity.INFO)
        if risk is Severity.INFO and cwe <= 0:
            continue  # pure inventory notes ("Modern Web Application"), not issues
        shown = evidence or f"{alert.get('param') or ''}".strip() or alert.get("name", "")
        if plugin in PLUGIN_RULES:
            findings.append(adapter.mapped(ctx, PLUGIN_RULES[plugin], plugin, shown,
                                           detail=f"ZAP: {alert.get('name')} ({alert.get('confidence')} confidence)",
                                           url=url))
        else:
            refs = [r for r in (alert.get("reference") or "").split() if r.startswith("http")]
            findings.append(adapter.unmapped(
                ctx, plugin, alert.get("name") or alert.get("alert") or f"ZAP rule {plugin}", risk,
                CONFIDENCE.get(alert.get("confidence", ""), Confidence.TENTATIVE), cwe,
                alert.get("description", ""), shown, alert.get("solution", ""), refs, url=url))
    return findings


class ZapAdapter(ToolAdapter):
    name = "zap"
    default_timeout = 120.0

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.transport = transport  # injectable for tests

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        base, key = zap_settings()
        started, t0 = datetime.now(timezone.utc), time.monotonic()
        summary = ToolRunSummary(tool=self.name, argv=["zap-api", "core/action/accessUrl", ctx.url], started_at=started)
        headers = {"X-ZAP-API-Key": key} if key else {}
        try:
            async with httpx.AsyncClient(base_url=base, headers=headers, timeout=60.0, transport=self.transport) as client:
                alerts = await asyncio.wait_for(self._scan(client, ctx.url), min(ctx.timeout, self.default_timeout))
                try:
                    await client.get("/JSON/core/action/deleteSiteNode/", params={"url": ctx.url})
                except httpx.HTTPError:
                    pass
        except asyncio.TimeoutError:
            summary.timed_out, summary.error = True, "timed out"
            return self._done(summary, t0)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            summary.error = f"ZAP API error: {type(exc).__name__}"
            return self._done(summary, t0)
        findings = parse(alerts, ctx, self)
        summary.exit_code, summary.finding_count = 0, len(findings)
        return self._done(summary, t0, findings)

    async def _scan(self, client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
        (await client.get("/JSON/core/action/accessUrl/", params={"url": url, "followRedirects": "false"})).raise_for_status()
        deadline = time.monotonic() + PSCAN_WAIT
        while time.monotonic() < deadline:
            pending = (await client.get("/JSON/pscan/view/recordsToScan/")).json()["recordsToScan"]
            if int(pending) == 0:
                break
            await asyncio.sleep(0.5)
        resp = await client.get("/JSON/alert/view/alerts/", params={"baseurl": url, "start": 0, "count": 1000})
        resp.raise_for_status()
        return resp.json()["alerts"]

    def _done(self, summary: ToolRunSummary, t0: float, findings: list[PassiveFinding] | None = None) -> AdapterResult:
        summary.duration_s = round(time.monotonic() - t0, 3)
        return AdapterResult(tool=self.name, findings=findings or [], run=summary)
