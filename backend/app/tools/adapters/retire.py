"""Retire.js: known-vulnerable JavaScript libraries, matched on file contents and names.

Scripts are downloaded by WAPTrix's own fetcher (rate-limited, size-capped, same host only), exactly as a
browser loading the page would; Retire.js then scans the local copies. Off-host scripts (CDNs) are never
fetched, because those hosts are outside the authorized scope.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.models.audit import ToolRunSummary
from app.models.finding import PassiveFinding
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, read_json, summarize_run

MAX_SCRIPTS = 20
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def parse(data: Any, ctx: AdapterContext, adapter: ToolAdapter, file_urls: dict[str, str]) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    for item in (data or {}).get("data", []):
        url = file_urls.get(item.get("file", ""), ctx.url)
        for result in item.get("results", []):
            vulns = result.get("vulnerabilities") or []
            if not vulns:
                continue
            component, version = result.get("component", "unknown"), result.get("version", "?")
            ids = sorted({cve for v in vulns for cve in (v.get("identifiers") or {}).get("CVE", [])})
            summaries = [f"[{v.get('severity', '?')}] {(v.get('identifiers') or {}).get('summary', '').strip()}"
                         for v in vulns]
            evidence = f"{component} {version} at {url}" + (f" ({', '.join(ids)})" if ids else "")
            findings.append(adapter.mapped(ctx, "JS-VULNERABLE-LIBRARY", f"{component}@{version}", evidence,
                                           detail="Retire.js advisories:\n" + "\n".join(summaries), url=ctx.url))
    return findings


class RetireAdapter(ToolAdapter):
    name = "retire"
    default_timeout = 180.0

    def applicable(self, ctx: AdapterContext) -> str | None:
        if ctx.fetch is None:
            return "no fetcher available"
        return None if ctx.script_urls else "page loads no same-host scripts"

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        assert ctx.fetch is not None
        js_dir = workdir / "js"
        js_dir.mkdir()
        file_urls: dict[str, str] = {}
        for index, url in enumerate(ctx.script_urls[:MAX_SCRIPTS]):
            if urlsplit(url).hostname != ctx.target.host:
                continue
            body = await ctx.fetch(url)
            if not body:
                continue
            name = _SAFE.sub("_", Path(urlsplit(url).path).name).strip(".") or "script.js"
            path = js_dir / f"{index:02d}" / name  # keep the original filename: Retire.js matches on it
            path.parent.mkdir()
            path.write_bytes(body)
            file_urls[str(path)] = url
        if not file_urls:
            return AdapterResult(tool=self.name, run=ToolRunSummary(tool=self.name, error="skipped: no script could be fetched"))

        out = workdir / "retire.json"
        argv = ["retire", "--jspath", str(js_dir), "--outputformat", "json", "--outputpath", str(out)]
        run = await self.invoke(argv, ctx)
        data = read_json(out)
        if data is None:  # exit code 13 just means "vulnerabilities found"
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no JSON output"))
        findings = parse(data, ctx, self, file_urls)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
