"""Security response header checks: CSP, HSTS, X-Frame-Options, XCTO, Referrer-Policy, Permissions-Policy."""

from __future__ import annotations

import re

from app.checks.base import AuditContext, PassiveCheck
from app.models.finding import PassiveFinding

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        tokens = chunk.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:  # first occurrence wins per CSP spec
            directives[name] = [t for t in tokens[1:]]
    return directives


def csp_weaknesses(policy: str) -> list[str]:
    directives = parse_csp(policy)
    issues: list[str] = []
    script_directive = "script-src" if "script-src" in directives else "default-src"
    sources = directives.get(script_directive)
    if sources is None:
        issues.append("no script-src or default-src directive (scripts unrestricted)")
        return issues
    lowered = [s.lower() for s in sources]
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered)
    if "'unsafe-inline'" in lowered and not has_nonce_or_hash:
        issues.append(f"{script_directive} allows 'unsafe-inline'")
    if "'unsafe-eval'" in lowered:
        issues.append(f"{script_directive} allows 'unsafe-eval'")
    for broad in ("*", "http:", "https:", "data:"):
        if broad in lowered and "'strict-dynamic'" not in lowered:
            issues.append(f"{script_directive} allows overly broad source {broad}")
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("object-src not restricted")
    return issues


def parse_hsts_max_age(value: str) -> int | None:
    match = re.search(r"max-age\s*=\s*\"?(\d+)\"?", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


class SecurityHeadersCheck(PassiveCheck):
    name = "headers"
    rule_ids = (
        "HDR-CSP-MISSING",
        "HDR-CSP-WEAK",
        "HDR-HSTS-MISSING",
        "HDR-HSTS-WEAK",
        "HDR-XFO-MISSING",
        "HDR-XCTO-MISSING",
        "HDR-REFERRER-MISSING",
        "HDR-PERMISSIONS-MISSING",
    )

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        primary = ctx.primary
        if primary is None:
            return []
        findings: list[PassiveFinding] = []
        url = primary.final_url

        csp_header = primary.header("content-security-policy")
        csp_meta = None
        if ctx.soup is not None:
            meta = ctx.soup.find("meta", attrs={"http-equiv": re.compile("^content-security-policy$", re.I)})
            if meta is not None and meta.get("content"):
                csp_meta = str(meta["content"])
        csp = csp_header or csp_meta

        if primary.is_html:
            if not csp:
                report_only = primary.header("content-security-policy-report-only")
                detail = (
                    "Only Content-Security-Policy-Report-Only is present, which does not enforce anything."
                    if report_only
                    else None
                )
                findings.append(
                    self.finding(
                        ctx,
                        "HDR-CSP-MISSING",
                        evidence=f"Report-Only: {report_only}" if report_only else "No Content-Security-Policy header or meta tag",
                        url=url,
                        detail=detail,
                    )
                )
            else:
                weaknesses = csp_weaknesses(csp)
                if weaknesses:
                    findings.append(
                        self.finding(
                            ctx,
                            "HDR-CSP-WEAK",
                            evidence=f"Content-Security-Policy: {csp}",
                            url=url,
                            detail="Weaknesses: " + "; ".join(weaknesses),
                        )
                    )

            frame_ancestors = "frame-ancestors" in parse_csp(csp_header) if csp_header else False
            xfo = primary.header("x-frame-options")
            if not xfo and not frame_ancestors:
                findings.append(
                    self.finding(ctx, "HDR-XFO-MISSING", evidence="No X-Frame-Options or CSP frame-ancestors", url=url)
                )
            elif xfo and xfo.strip().upper().split()[0] not in ("DENY", "SAMEORIGIN") and not frame_ancestors:
                findings.append(
                    self.finding(
                        ctx,
                        "HDR-XFO-MISSING",
                        evidence=f"X-Frame-Options: {xfo}",
                        url=url,
                        detail="The X-Frame-Options value is not DENY or SAMEORIGIN and is ignored by modern browsers.",
                    )
                )

            if not primary.header("referrer-policy") and not self._meta(ctx, "referrer"):
                findings.append(self.finding(ctx, "HDR-REFERRER-MISSING", evidence="No Referrer-Policy header", url=url))
            if not primary.header("permissions-policy"):
                findings.append(
                    self.finding(ctx, "HDR-PERMISSIONS-MISSING", evidence="No Permissions-Policy header", url=url)
                )

        xcto = primary.header("x-content-type-options")
        if not xcto or xcto.strip().lower() != "nosniff":
            findings.append(
                self.finding(
                    ctx,
                    "HDR-XCTO-MISSING",
                    evidence=f"X-Content-Type-Options: {xcto}" if xcto else "No X-Content-Type-Options header",
                    url=url,
                )
            )

        if ctx.https_ok and ctx.https is not None:
            hsts = ctx.https.header("strict-transport-security")
            https_url = ctx.https.final_url
            if not hsts:
                findings.append(
                    self.finding(ctx, "HDR-HSTS-MISSING", evidence="No Strict-Transport-Security header", url=https_url)
                )
            else:
                max_age = parse_hsts_max_age(hsts)
                if max_age is None or max_age < HSTS_MIN_MAX_AGE:
                    findings.append(
                        self.finding(
                            ctx,
                            "HDR-HSTS-WEAK",
                            evidence=f"Strict-Transport-Security: {hsts}",
                            url=https_url,
                            detail=f"Parsed max-age: {max_age if max_age is not None else 'absent'} seconds.",
                        )
                    )
        return findings

    @staticmethod
    def _meta(ctx: AuditContext, name: str) -> str | None:
        if ctx.soup is None:
            return None
        tag = ctx.soup.find("meta", attrs={"name": re.compile(f"^{name}$", re.I)})
        return str(tag.get("content")) if tag is not None and tag.get("content") else None
