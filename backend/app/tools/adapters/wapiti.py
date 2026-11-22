"""Wapiti: black-box web application scanner (S4 testing).

Active: crawls the application and injects payloads into parameters and forms. The crawl is held to the
target folder (--scope folder) so it never wanders off the authorized host, the session is flushed each
run, and a wall-clock budget caps it. Findings are read from Wapiti's JSON report, grouped by category.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import SESSION_KILLER_PATHS, AdapterContext, AdapterResult, ToolAdapter, read_json, summarize_run

# Wapiti category name -> (CWE, severity). Categories not listed fall back to MEDIUM with no CWE.
CATEGORY = {
    "SQL Injection": (89, Severity.HIGH),
    "Blind SQL Injection": (89, Severity.HIGH),
    "Command execution": (78, Severity.CRITICAL),
    "Path Traversal": (22, Severity.HIGH),
    "Cross Site Scripting": (79, Severity.MEDIUM),
    "Stored Cross Site Scripting": (79, Severity.HIGH),
    "Server Side Request Forgery": (918, Severity.HIGH),
    "Cross Site Request Forgery": (352, Severity.MEDIUM),
    "Open Redirect": (601, Severity.MEDIUM),
    "Secure Flag cookie": (614, Severity.LOW),
    "HttpOnly Flag cookie": (1004, Severity.LOW),
    "Content Security Policy Configuration": (693, Severity.LOW),
    "HTTP Secure Headers": (693, Severity.LOW),
}
_CWE_RE = re.compile(r"CWE-(\d+)")


def _cwe_from_classification(entry: dict[str, Any]) -> int | None:
    for key in (entry.get("ref") or {}):
        if match := _CWE_RE.search(str(key)):
            return int(match.group(1))
    if match := _CWE_RE.search(str(entry.get("desc", ""))):
        return int(match.group(1))
    return None


def parse(data: Any, ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    if not isinstance(data, dict):
        return []
    vulnerabilities: dict[str, list] = data.get("vulnerabilities") or {}
    classifications: dict[str, dict] = data.get("classifications") or {}
    findings: list[PassiveFinding] = []
    for category, entries in vulnerabilities.items():
        if not entries:
            continue
        cwe, severity = CATEGORY.get(category, (None, Severity.MEDIUM))
        meta = classifications.get(category) or {}
        cwe = cwe or _cwe_from_classification(meta)
        solution = meta.get("sol") or meta.get("solution") or ""
        description = meta.get("desc") or category
        for i, entry in enumerate(entries):
            path = entry.get("path") or "/"
            location = urljoin(ctx.url, path) if not str(path).startswith("http") else path
            param = entry.get("parameter") or ""
            method = entry.get("method") or "GET"
            info = entry.get("info") or category
            evidence = f"{method} {location}" + (f" [param: {param}]" if param else "")
            request = (entry.get("http_request") or "").strip()
            findings.append(adapter.unmapped(
                ctx, f"{category}-{i}", category, severity, Confidence.FIRM, cwe,
                f"{description}\n\n{info}".strip(), f"{evidence}\n{request}".strip(), solution, url=location))
    return findings


class WapitiAdapter(ToolAdapter):
    name = "wapiti"
    default_timeout = 900.0

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "wapiti.json"
        budget = int(min(ctx.timeout, self.default_timeout))
        argv = ["wapiti", "-u", ctx.url, "-f", "json", "-o", str(out), "--scope", "folder",
                "--flush-session", "--max-scan-time", str(budget), "-v", "0"]
        if ctx.cookie:  # stay logged in: send the session, never crawl the logout link
            argv += ["-H", f"Cookie: {ctx.cookie}"]
            for path in SESSION_KILLER_PATHS:  # -x wants full URLs
                argv += ["-x", urljoin(ctx.url, path)]
        run = await self.invoke(argv, ctx)
        data = read_json(out)
        if data is None:
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no JSON report"))
        findings = parse(data, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
