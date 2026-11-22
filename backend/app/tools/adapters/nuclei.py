"""Nuclei: template-based active checks for known misconfigurations and CVEs (S4 testing).

Active: sends the probes each matched template defines. Run with update checks and the interactsh
out-of-band server disabled (no third-party callbacks), the request rate pinned to the audit's own
per-host cap, and findings read from JSONL. Each result keeps its template id and CWE/CVE classification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, summarize_run

SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
            "low": Severity.LOW, "info": Severity.INFO, "unknown": Severity.INFO}


def _cwe(classification: dict[str, Any]) -> str | int | None:
    cwes = classification.get("cwe-id") or classification.get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    return cwes[0] if cwes else None


def parse(records: list[dict[str, Any]], ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    seen: set[tuple[str, str]] = set()
    for rec in records:
        template = rec.get("template-id") or rec.get("templateID") or "unknown"
        info = rec.get("info") or {}
        matched = rec.get("matched-at") or rec.get("matched") or ctx.url
        if (template, matched) in seen:
            continue
        seen.add((template, matched))
        classification = info.get("classification") or {}
        severity = SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        extracted = rec.get("extracted-results") or []
        evidence = f"{rec.get('type', 'http')} {matched}" + (f" → {', '.join(map(str, extracted))}" if extracted else "")
        cve = classification.get("cve-id") or classification.get("cve")
        detail = info.get("description") or info.get("name") or template
        if cve:
            detail = f"{detail}\n{', '.join(cve) if isinstance(cve, list) else cve}"
        findings.append(adapter.unmapped(
            ctx, template, info.get("name") or template, severity,
            Confidence.FIRM, _cwe(classification), detail, evidence,
            info.get("remediation", ""), [r for r in refs if str(r).startswith("http")], url=matched))
    return findings


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    default_timeout = 600.0

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "nuclei.jsonl"
        # Scan the S3 map's endpoints (seeds first), not just the root, so templates fire on
        # /metrics, /ftp, parameterised REST endpoints and the like that the root alone would miss.
        targets = ctx.scan_urls()
        targets_file = workdir / "targets.txt"
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        argv = ["nuclei", "-l", str(targets_file), "-jsonl", "-o", str(out), "-disable-update-check",
                "-no-interactsh", "-rate-limit", "50", "-timeout", "10", "-retries", "1",
                "-as",  # automatic scan: pick templates for the detected tech stack (much faster than all)
                "-severity", "low,medium,high,critical", "-silent"]
        if ctx.cookie:
            argv += ["-H", f"Cookie: {ctx.cookie}"]
        run = await self.invoke(argv, ctx)
        records: list[dict] = []
        if out.exists():
            for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
        findings = parse(records, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
