"""Transport security checks: HTTPS availability/redirect, TLS protocol & cipher, certificate, mixed content."""

from __future__ import annotations

from app.checks.base import AuditContext, PassiveCheck
from app.models.finding import PassiveFinding

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "DES", "NULL", "EXP", "ANON", "ADH", "AECDH", "MD5")
EXPIRY_WARNING_DAYS = 30

# tag -> attribute carrying a sub-resource URL
ACTIVE_RESOURCES = {
    "script": "src",
    "iframe": "src",
    "frame": "src",
    "object": "data",
    "embed": "src",
}
PASSIVE_RESOURCES = {"img": "src", "audio": "src", "video": "src", "source": "src", "track": "src"}


def is_weak_cipher(name: str | None, bits: int | None) -> bool:
    if not name:
        return False
    upper = name.upper()
    if any(marker in upper for marker in WEAK_CIPHER_MARKERS):
        return True
    return bits is not None and 0 < bits < 128


class TransportTLSCheck(PassiveCheck):
    name = "transport_tls"
    rule_ids = (
        "TLS-NO-HTTPS",
        "TLS-NO-REDIRECT",
        "TLS-DEPRECATED-PROTOCOL",
        "TLS-WEAK-CIPHER",
        "TLS-CERT-EXPIRED",
        "TLS-CERT-EXPIRING",
        "TLS-CERT-HOSTNAME-MISMATCH",
        "TLS-CERT-UNTRUSTED",
        "TLS-MIXED-CONTENT-ACTIVE",
        "TLS-MIXED-CONTENT-PASSIVE",
    )

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        findings.extend(self._https_enforcement(ctx))
        findings.extend(self._tls(ctx))
        findings.extend(self._mixed_content(ctx))
        return findings

    def _https_enforcement(self, ctx: AuditContext) -> list[PassiveFinding]:
        if not ctx.http_ok or ctx.http is None:
            return []
        http = ctx.http
        if not ctx.https_ok:
            reason = ctx.https.error if ctx.https else "not attempted"
            return [
                self.finding(
                    ctx,
                    "TLS-NO-HTTPS",
                    evidence=f"{http.url} -> HTTP {http.status_code}; HTTPS: {reason}",
                    url=http.url,
                )
            ]
        final = http.final_url or ""
        redirected = final.startswith("https://") or (http.stopped_offscope or "").startswith("https://")
        if not redirected:
            return [
                self.finding(
                    ctx,
                    "TLS-NO-REDIRECT",
                    evidence=f"GET {http.url} -> HTTP {http.status_code} served over cleartext (final URL {final})",
                    url=http.url,
                )
            ]
        return []

    def _tls(self, ctx: AuditContext) -> list[PassiveFinding]:
        tls = ctx.tls
        if tls is None or tls.error:
            return []
        findings: list[PassiveFinding] = []
        url = ctx.target.https_url()

        deprecated = sorted(
            {p for p in [tls.protocol, *tls.legacy_protocols_accepted] if p in DEPRECATED_PROTOCOLS}
        )
        if deprecated:
            findings.append(
                self.finding(
                    ctx,
                    "TLS-DEPRECATED-PROTOCOL",
                    evidence=f"Negotiated: {tls.protocol}; legacy handshake accepted: {', '.join(deprecated)}",
                    url=url,
                )
            )
        if is_weak_cipher(tls.cipher, tls.cipher_bits):
            findings.append(
                self.finding(
                    ctx,
                    "TLS-WEAK-CIPHER",
                    evidence=f"{tls.protocol} {tls.cipher} ({tls.cipher_bits} bits)",
                    url=url,
                )
            )

        expired = False
        if tls.cert_not_after and tls.cert_not_before:
            if ctx.now > tls.cert_not_after or ctx.now < tls.cert_not_before:
                expired = True
                findings.append(
                    self.finding(
                        ctx,
                        "TLS-CERT-EXPIRED",
                        evidence=(
                            f"Valid {tls.cert_not_before.isoformat()} to {tls.cert_not_after.isoformat()}; "
                            f"observed {ctx.now.isoformat(timespec='seconds')}"
                        ),
                        url=url,
                    )
                )
            elif tls.days_to_expiry is not None and tls.days_to_expiry < EXPIRY_WARNING_DAYS:
                findings.append(
                    self.finding(
                        ctx,
                        "TLS-CERT-EXPIRING",
                        evidence=f"Certificate expires {tls.cert_not_after.isoformat()} ({tls.days_to_expiry} days)",
                        url=url,
                    )
                )

        mismatch = tls.hostname_match is False
        if mismatch:
            names = ", ".join(tls.san[:10]) or tls.cert_subject or "none"
            findings.append(
                self.finding(
                    ctx,
                    "TLS-CERT-HOSTNAME-MISMATCH",
                    evidence=f"Host {ctx.target.host} not in certificate names: {names}",
                    url=url,
                )
            )

        if tls.trusted is False:
            message = (tls.verify_error or "").lower()
            covered = (mismatch and "hostname" in message) or (expired and "expired" in message)
            if not covered:
                evidence = f"Verification error: {tls.verify_error}; issuer: {tls.cert_issuer}"
                if tls.self_signed:
                    evidence += " (self-signed)"
                findings.append(self.finding(ctx, "TLS-CERT-UNTRUSTED", evidence=evidence, url=url))
        return findings

    def _mixed_content(self, ctx: AuditContext) -> list[PassiveFinding]:
        if not ctx.primary_is_https or ctx.soup is None:
            return []
        active: list[str] = []
        passive: list[str] = []
        for tag_name, attr in ACTIVE_RESOURCES.items():
            for tag in ctx.soup.find_all(tag_name):
                value = str(tag.get(attr) or "").strip()
                if value.lower().startswith("http://"):
                    active.append(f"<{tag_name} {attr}=\"{value}\">")
        for tag in ctx.soup.find_all("link"):
            rel = " ".join(tag.get("rel") or []).lower()
            href = str(tag.get("href") or "").strip()
            if href.lower().startswith("http://") and ("stylesheet" in rel or "preload" in rel or "modulepreload" in rel):
                active.append(f"<link rel=\"{rel}\" href=\"{href}\">")
        for tag_name, attr in PASSIVE_RESOURCES.items():
            for tag in ctx.soup.find_all(tag_name):
                value = str(tag.get(attr) or "").strip()
                if value.lower().startswith("http://"):
                    passive.append(f"<{tag_name} {attr}=\"{value}\">")

        url = ctx.primary.final_url if ctx.primary else None
        findings: list[PassiveFinding] = []
        if active:
            findings.append(
                self.finding(
                    ctx,
                    "TLS-MIXED-CONTENT-ACTIVE",
                    evidence="\n".join(sorted(set(active))[:8]),
                    url=url,
                    detail=f"{len(set(active))} insecure active resource reference(s) found.",
                )
            )
        if passive:
            findings.append(
                self.finding(
                    ctx,
                    "TLS-MIXED-CONTENT-PASSIVE",
                    evidence="\n".join(sorted(set(passive))[:8]),
                    url=url,
                    detail=f"{len(set(passive))} insecure passive resource reference(s) found.",
                )
            )
        return findings
