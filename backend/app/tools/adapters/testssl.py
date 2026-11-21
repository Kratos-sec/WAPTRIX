"""testssl.sh: TLS configuration cross-check.

Runs only the protocol, server-defaults (certificate), standard cipher category and forward-secrecy
sections. The vulnerability section (-U: Heartbleed, ROBOT, ...) is never requested.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, read_json, summarize_run

SECTIONS = ["--protocols", "--server-defaults", "--std", "--fs"]
DEPRECATED = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLS 1.0", "TLS1_1": "TLS 1.1"}
WEAK_CIPHER_LISTS = {"cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW", "cipherlist_3DES_IDEA"}
# Covered by a mapped finding above, or bookkeeping rather than a finding.
CONSUMED = {*DEPRECATED, *WEAK_CIPHER_LISTS, "cert_chain_of_trust", "cert_trust", "cert_expirationStatus",
            "cert_notAfter", "engine_problem", "scanTime", "service"}
SEVERITY = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _base_id(entry_id: str) -> str:
    return entry_id.split(" ")[0]  # multi-certificate hosts suffix ids with " <cert#N>"


def parse(data: Any, ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    entries = [e for e in data if isinstance(e, dict) and "id" in e] if isinstance(data, list) else []
    findings: list[PassiveFinding] = []

    offered = [DEPRECATED[e["id"]] for e in entries if e["id"] in DEPRECATED and e["finding"].startswith("offered")]
    if offered:
        findings.append(adapter.mapped(ctx, "TLS-DEPRECATED-PROTOCOL", "protocols", f"Server offers: {', '.join(offered)}"))
    weak = [e["id"].removeprefix("cipherlist_") for e in entries
            if e["id"] in WEAK_CIPHER_LISTS and e["finding"].startswith("offered")]
    if weak:
        findings.append(adapter.mapped(ctx, "TLS-WEAK-CIPHER", "cipherlist", f"Weak cipher categories offered: {', '.join(weak)}"))

    seen: set[tuple[str, str]] = set()
    for entry in entries:
        base, severity, text = _base_id(entry["id"]), entry.get("severity", ""), entry.get("finding", "")
        if base == "cert_chain_of_trust" and severity in SEVERITY:
            key = ("TLS-CERT-UNTRUSTED", "")
            if key not in seen:
                findings.append(adapter.mapped(ctx, "TLS-CERT-UNTRUSTED", entry["id"], f"Chain of trust: {text}"))
        elif base == "cert_trust" and "does not match" in text:
            key = ("TLS-CERT-HOSTNAME-MISMATCH", "")
            if key not in seen:
                findings.append(adapter.mapped(ctx, "TLS-CERT-HOSTNAME-MISMATCH", entry["id"], text))
        elif base == "cert_expirationStatus" and text.startswith("expired"):
            key = ("TLS-CERT-EXPIRED", "")
            if key not in seen:
                findings.append(adapter.mapped(ctx, "TLS-CERT-EXPIRED", entry["id"], text))
        elif base == "cert_expirationStatus" and text.startswith("expires <"):
            key = ("TLS-CERT-EXPIRING", "")
            if key not in seen:
                findings.append(adapter.mapped(ctx, "TLS-CERT-EXPIRING", entry["id"], text))
        elif base not in CONSUMED and severity in SEVERITY:
            key = (base, text)
            if key not in seen:
                findings.append(adapter.unmapped(
                    ctx, base, f"{base}: {text}"[:120], SEVERITY[severity], Confidence.FIRM,
                    entry.get("cwe") or (295 if base.startswith("cert") else 326),
                    f"testssl.sh rated the '{base}' check {severity}: {text}", text,
                    references=["https://testssl.sh/doc/testssl.1.html"]))
        else:
            continue
        seen.add(key)
    return findings


class TestSSLAdapter(ToolAdapter):
    name = "testssl"
    default_timeout = 600.0

    def applicable(self, ctx: AdapterContext) -> str | None:
        return None if ctx.https_ok else "no HTTPS endpoint"

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "testssl.json"
        argv = ["testssl", "--quiet", "--color", "0", "--warnings", "off", "--ip", "one",
                "--connect-timeout", "10", "--openssl-timeout", "10", *SECTIONS,
                "--jsonfile", str(out), f"{ctx.target.host}:{ctx.target.tls_port}"]
        run = await self.invoke(argv, ctx)
        data = read_json(out)
        if data is None:
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no JSON output"))
        findings = parse(data, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
