"""SSLyze: TLS protocol/cipher enumeration and certificate analysis.

Only configuration scans are scheduled. The vulnerability probes SSLyze runs by default (Heartbleed,
ROBOT, OpenSSL CCS injection) send crafted handshakes, so they are never requested here.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from app.models.finding import Confidence, PassiveFinding, Severity
from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter, read_json, summarize_run, utc

SCAN_COMMANDS = ["--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
                 "--elliptic_curves", "--fallback", "--compression"]
DEPRECATED = {"ssl_2_0_cipher_suites": "SSLv2", "ssl_3_0_cipher_suites": "SSLv3",
              "tls_1_0_cipher_suites": "TLS 1.0", "tls_1_1_cipher_suites": "TLS 1.1"}
ALL_SUITES = [*DEPRECATED, "tls_1_2_cipher_suites", "tls_1_3_cipher_suites"]
_WEAK_MARKERS = ("NULL", "EXPORT", "RC4", "_DES_", "DES40", "3DES", "_MD5", "ANON")
EXPIRY_WARNING_DAYS = 30


def _weak(cipher: dict) -> bool:
    name = cipher.get("name", "").upper()
    return bool(cipher.get("is_anonymous")) or (cipher.get("key_size") or 0) < 128 or any(m in name for m in _WEAK_MARKERS)


def _completed(scan: dict, key: str) -> dict | None:
    entry = scan.get(key) or {}
    return entry.get("result") if entry.get("status") == "COMPLETED" else None


def parse(data: Any, ctx: AdapterContext, adapter: ToolAdapter) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    results = (data or {}).get("server_scan_results") or []
    if not results or results[0].get("scan_status") != "COMPLETED":
        return findings
    scan = results[0]["scan_result"]
    scanned_at = utc(data["date_scans_started"]) if data.get("date_scans_started") else None

    offered = [label for key, label in DEPRECATED.items()
               if (r := _completed(scan, key)) and r.get("is_tls_version_supported")]
    if offered:
        findings.append(adapter.mapped(ctx, "TLS-DEPRECATED-PROTOCOL", "deprecated_protocols",
                                       f"Server accepts: {', '.join(offered)}"))

    weak: list[str] = []
    for key in ALL_SUITES:
        result = _completed(scan, key) or {}
        weak += [a["cipher_suite"]["name"] for a in result.get("accepted_cipher_suites", []) if _weak(a["cipher_suite"])]
    if weak:
        findings.append(adapter.mapped(ctx, "TLS-WEAK-CIPHER", "weak_ciphers",
                                       "Accepted weak cipher suites: " + ", ".join(sorted(set(weak)))))

    cert_info = _completed(scan, "certificate_info")
    for deployment in (cert_info or {}).get("certificate_deployments", [])[:1]:
        findings += _certificate(deployment, ctx, adapter, scanned_at)

    if (r := _completed(scan, "tls_compression")) and r.get("supports_compression"):
        findings.append(adapter.unmapped(
            ctx, "compression", "TLS compression enabled", Severity.MEDIUM, Confidence.CERTAIN, 310,
            "The server accepts TLS-level compression, which enables the CRIME attack on encrypted session data.",
            "supports_compression: true", "Disable TLS compression on the server.",
            ["https://en.wikipedia.org/wiki/CRIME"]))
    if (r := _completed(scan, "tls_fallback_scsv")) and r.get("supports_fallback_scsv") is False:
        findings.append(adapter.unmapped(
            ctx, "no_fallback_scsv", "TLS_FALLBACK_SCSV not supported", Severity.LOW, Confidence.CERTAIN, 757,
            "The server does not honour TLS_FALLBACK_SCSV (RFC 7507), so clients that retry with a lower protocol "
            "version cannot be protected from forced downgrades.",
            "supports_fallback_scsv: false", "Enable TLS_FALLBACK_SCSV, or drop support for protocols below TLS 1.2.",
            ["https://datatracker.ietf.org/doc/html/rfc7507"]))
    return findings


def _certificate(deployment: dict, ctx: AdapterContext, adapter: ToolAdapter,
                 scanned_at: datetime | None) -> list[PassiveFinding]:
    findings: list[PassiveFinding] = []
    validations = deployment.get("path_validation_results") or []
    if validations and all(v.get("validation_error") for v in validations):
        stores = ", ".join(v["trust_store"]["name"] for v in validations)
        error = next((v["validation_error"] for v in validations if v["trust_store"]["name"] == "Mozilla"),
                     validations[0]["validation_error"])
        findings.append(adapter.mapped(ctx, "TLS-CERT-UNTRUSTED", "path_validation",
                                       f"Chain did not validate against any trust store ({stores}): {error}"))
    if deployment.get("verified_chain_has_sha1_signature"):
        findings.append(adapter.unmapped(
            ctx, "sha1_chain", "Certificate chain signed with SHA-1", Severity.MEDIUM, Confidence.CERTAIN, 328,
            "A certificate in the verified chain uses a SHA-1 signature, which is collision-prone and rejected by "
            "modern browsers.", "verified_chain_has_sha1_signature: true",
            "Reissue the certificate chain with SHA-256 or stronger signatures."))

    chain = deployment.get("received_certificate_chain") or []
    if chain and scanned_at:
        leaf = chain[0]
        not_after, not_before = utc(leaf["not_valid_after"]), utc(leaf["not_valid_before"])
        days = (not_after - scanned_at).days
        if not_after < scanned_at or not_before > scanned_at:
            findings.append(adapter.mapped(ctx, "TLS-CERT-EXPIRED", "validity",
                                           f"Valid {leaf['not_valid_before']} to {leaf['not_valid_after']}"))
        elif days < EXPIRY_WARNING_DAYS:
            findings.append(adapter.mapped(ctx, "TLS-CERT-EXPIRING", "validity",
                                           f"Certificate expires {leaf['not_valid_after']} ({days} days)"))
    return findings


class SSLyzeAdapter(ToolAdapter):
    name = "sslyze"
    default_timeout = 300.0

    def applicable(self, ctx: AdapterContext) -> str | None:
        return None if ctx.https_ok else "no HTTPS endpoint"

    async def execute(self, ctx: AdapterContext, workdir: Path) -> AdapterResult:
        out = workdir / "sslyze.json"
        argv = ["sslyze", "--quiet", "--mozilla_config=disable", "--slow_connection", *SCAN_COMMANDS,
                f"--json_out={out}", f"{ctx.target.host}:{ctx.target.tls_port}"]
        run = await self.invoke(argv, ctx)
        data = read_json(out)
        if data is None:
            return AdapterResult(tool=self.name, run=summarize_run(run, 0, error=run.error or "no JSON output"))
        findings = parse(data, ctx, self)
        return AdapterResult(tool=self.name, findings=findings, run=summarize_run(run, len(findings)))
