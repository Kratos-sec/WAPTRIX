"""WhatWeb: technology fingerprinting from a single page load (aggression level 1, no redirects)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.models.audit import Technology
from app.models.finding import PassiveFinding
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, read_json, summarize_run

# Plugins that describe the request/response rather than a technology.
_NOISE = {"Country", "IP", "Title", "HTML5", "Script", "Cookies", "PasswordField", "UncommonHeaders",
          "RedirectLocation", "Email", "Meta-Author", "Frame", "Strict-Transport-Security", "X-Frame-Options",
          "X-XSS-Protection", "X-UA-Compatible", "Content-Language", "Open-Graph-Protocol", "MetaGenerator"}
_HAS_VERSION = re.compile(r"\d+\.\d+")


def parse(data: Any, ctx: AdapterContext, adapter: ToolAdapter) -> tuple[list[Technology], list[PassiveFinding]]:
    technologies: dict[tuple[str, str | None], Technology] = {}
    findings: list[PassiveFinding] = []
    for entry in data if isinstance(data, list) else []:
        plugins: dict[str, dict] = entry.get("plugins") or {}
        for name, info in plugins.items():
            if name in _NOISE:
                continue
            versions = info.get("version") or []
            strings = info.get("string") or []
            if name == "HTTPServer":
                for banner in strings:
                    if _HAS_VERSION.search(banner):
                        findings.append(adapter.mapped(ctx, "DISC-SERVER-VERSION", "HTTPServer", f"Server: {banner}"))
                continue
            if name == "X-Powered-By":
                for value in strings:
                    if _HAS_VERSION.search(value):
                        findings.append(adapter.mapped(ctx, "DISC-VERSION-HEADER", "X-Powered-By", f"X-Powered-By: {value}"))
            for version in versions or [None]:
                technologies.setdefault((name, version), Technology(name=name, version=version, source=adapter.name))
    return list(technologies.values()), findings


class WhatWebAdapter(ToolAdapter):
    name = "whatweb"
    default_timeout = 60.0

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "whatweb.json"
        argv = ["whatweb", "--aggression=1", "--follow-redirect=never", "--color=never", "--no-errors",
                "--quiet", f"--log-json={out}", ctx.url]
        run = await self.invoke(argv, ctx)
        data = read_json(out)
        if data is None:
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no JSON output"))
        technologies, findings = parse(data, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, technologies=technologies,
                             run=summarize_run(run, len(findings)))
