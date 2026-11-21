"""Nikto: web server misconfiguration and dangerous default files (S4 testing).

Active: requests many known-risky paths and inspects the server's responses. Bounded by a wall-clock
budget (-maxtime), run non-interactively, output read as JSON. Each item keeps its Nikto/OSVDB id.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, read_json, summarize_run


def _vulnerabilities(data: Any) -> list[dict]:
    # Nikto JSON is either a host object or a single-element list of host objects.
    if isinstance(data, list):
        return [v for host in data if isinstance(host, dict) for v in (host.get("vulnerabilities") or [])]
    if isinstance(data, dict):
        return list(data.get("vulnerabilities") or [])
    return []


def parse(data: Any, ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    seen: set[str] = set()
    for vuln in _vulnerabilities(data):
        ref = str(vuln.get("id") or vuln.get("OSVDB") or vuln.get("niktoid") or len(findings))
        msg = (vuln.get("msg") or vuln.get("message") or "").strip()
        if not msg or ref in seen:
            continue
        seen.add(ref)
        path = vuln.get("url") or vuln.get("uri") or "/"
        location = urljoin(ctx.url, path) if not str(path).startswith("http") else path
        method = vuln.get("method") or "GET"
        refs = [r for r in [vuln.get("references")] if r and str(r).startswith("http")]
        findings.append(adapter.unmapped(
            ctx, ref, msg[:120], Severity.MEDIUM, Confidence.TENTATIVE, None,
            msg, f"{method} {location}", references=refs, url=location))
    return findings


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    default_timeout = 600.0

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "nikto.json"
        budget = int(min(ctx.timeout, self.default_timeout))
        argv = ["nikto", "-h", ctx.url, "-Format", "json", "-output", str(out),
                "-maxtime", f"{budget}s", "-ask", "no", "-nointeractive"]
        run = await self.invoke(argv, ctx)
        data = read_json(out)
        if data is None:
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no JSON output"))
        findings = parse(data, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
