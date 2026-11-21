"""Nmap: TCP connect port scan with light service/version detection (S3 enumeration).

Active: opens real TCP connections to the target and reads service banners. A connect scan (-sT) is
used instead of SYN so the adapter needs no raw-socket privileges and behaves identically on macOS,
Linux and inside the container. No host discovery (-Pn: the host is already resolved and in scope), no
NSE scripts, no OS fingerprinting — only the ports and the service versions the banners reveal.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, summarize_run

TOP_PORTS = 100


def _service_text(service: ElementTree.Element | None) -> tuple[str, bool]:
    if service is None:
        return "", False
    name = service.get("name") or ""
    product = service.get("product") or ""
    version = service.get("version") or ""
    extra = service.get("extrainfo") or ""
    parts = [p for p in (name, product, version, extra) if p]
    return " ".join(parts), bool(product or version)


def parse(xml_text: str, ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return findings
    for host in root.iter("host"):
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid") or "?"
            proto = port.get("protocol") or "tcp"
            descr, has_version = _service_text(port.find("service"))
            ref = f"{proto}-{portid}"
            evidence = f"{portid}/{proto} open {descr}".strip()
            if has_version:
                findings.append(adapter.unmapped(
                    ctx, ref, f"Service version exposed on {portid}/{proto}", Severity.LOW, Confidence.FIRM,
                    200, "The service on this port advertises its product and version in the banner, which "
                    "lets an attacker look up version-specific vulnerabilities.", evidence,
                    "Suppress or genericize service version banners where the software permits it."))
            else:
                findings.append(adapter.unmapped(
                    ctx, ref, f"Open port {portid}/{proto}", Severity.INFO, Confidence.CERTAIN, None,
                    "An open TCP port reachable from the scanning host.", evidence,
                    "Confirm the port is meant to be internet-facing; close or firewall it otherwise."))
    return findings


class NmapAdapter(ToolAdapter):
    name = "nmap"
    default_timeout = 300.0

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "nmap.xml"
        budget = int(min(ctx.timeout, self.default_timeout))
        argv = ["nmap", "-sT", "-Pn", "-sV", "--version-light", "--top-ports", str(TOP_PORTS),
                "--host-timeout", f"{budget}s", "-oX", str(out), ctx.target.host]
        run = await self.invoke(argv, ctx)
        xml_text = out.read_text(encoding="utf-8", errors="replace") if out.exists() else run.stdout
        if not xml_text.strip():
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no XML output"))
        findings = parse(xml_text, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
