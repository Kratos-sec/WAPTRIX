"""sqlmap: confirm SQL injection candidates, detection only (S5 confirmation).

Active: sends crafted SQL payloads to the URL's parameters. Held to the lowest aggression (--level 1
--risk 1), fully non-interactive (--batch), and strictly detection: no --dump, no --os-shell, no file
read/write, so it confirms injectability without exfiltrating data. Only URLs that carry parameters are
scanned — a URL with nothing to inject is skipped. Confirmed injection points are read from stdout.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, summarize_run

_PARAM = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<place>\w+)\)\s*$", re.MULTILINE)
_TYPE = re.compile(r"^\s*Type:\s*(?P<type>.+?)\s*$", re.MULTILINE)
_MARKER = "the following injection point"


def parse(stdout: str, ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    if _MARKER not in stdout:
        return []
    body = stdout[stdout.index(_MARKER):]
    findings: list[PassiveFinding] = []
    params = list(_PARAM.finditer(body))
    for idx, match in enumerate(params):
        start = match.end()
        end = params[idx + 1].start() if idx + 1 < len(params) else len(body)
        techniques = [t.group("type") for t in _TYPE.finditer(body[start:end])]
        name, place = match.group("name"), match.group("place")
        evidence = f"Parameter {name} ({place}) injectable via: {', '.join(techniques) or 'confirmed'}"
        findings.append(adapter.unmapped(
            ctx, f"{place}-{name}", "SQL injection confirmed", Severity.CRITICAL, Confidence.CERTAIN, 89,
            "sqlmap confirmed this parameter is injectable. Detection only — no data was extracted.",
            evidence, "Use parameterized queries / prepared statements and validate input server-side.",
            ["https://owasp.org/www-community/attacks/SQL_Injection"]))
    return findings


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    default_timeout = 900.0
    per_endpoint = True

    def applicable(self, ctx: AdapterContext) -> str | None:
        if not urlsplit(ctx.url).query:
            return "URL has no parameters to test"
        return None

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        argv = ["sqlmap", "-u", ctx.url, "--batch", "--level", "1", "--risk", "1",
                "--disable-coloring", "--flush-session", "--output-dir", str(workdir)]
        if ctx.cookie:
            argv += [f"--cookie={ctx.cookie}"]
        run = await self.invoke(argv, ctx)
        findings = parse(run.stdout, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
