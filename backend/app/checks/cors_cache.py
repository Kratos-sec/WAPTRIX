"""Passive CORS policy review and cache-control of sensitive responses.

No Origin header is forged: only the CORS headers the server volunteers on a normal GET are reviewed.
"""

from __future__ import annotations

from app.checks.base import AuditContext, PassiveCheck
from app.checks.cookies import collect_cookies
from app.models.finding import PassiveFinding


class CorsCacheCheck(PassiveCheck):
    name = "cors_cache"
    rule_ids = ("CORS-WILDCARD-CREDENTIALS", "CORS-NULL-ORIGIN", "CORS-WILDCARD", "CACHE-SENSITIVE-NO-STORE")

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        primary = ctx.primary
        if primary is None:
            return []
        findings: list[PassiveFinding] = []
        url = primary.final_url

        acao = (primary.header("access-control-allow-origin") or "").strip()
        acac = (primary.header("access-control-allow-credentials") or "").strip().lower() == "true"
        cors_evidence = f"Access-Control-Allow-Origin: {acao}" + (
            "\nAccess-Control-Allow-Credentials: true" if acac else ""
        )
        if acao == "*" and acac:
            findings.append(self.finding(ctx, "CORS-WILDCARD-CREDENTIALS", evidence=cors_evidence, url=url))
        elif acao.lower() == "null":
            findings.append(self.finding(ctx, "CORS-NULL-ORIGIN", evidence=cors_evidence, url=url))
        elif acao == "*":
            findings.append(self.finding(ctx, "CORS-WILDCARD", evidence=cors_evidence, url=url))

        reasons: list[str] = []
        session_cookies = [c.name for c in collect_cookies(ctx) if c.is_session_like]
        if session_cookies:
            reasons.append(f"sets session cookie(s): {', '.join(sorted(set(session_cookies)))}")
        if ctx.soup is not None and ctx.soup.find("input", attrs={"type": lambda t: t and t.lower() == "password"}):
            reasons.append("contains a password input")
        if reasons:
            cache_control = (primary.header("cache-control") or "").lower()
            if "no-store" not in cache_control:
                findings.append(
                    self.finding(
                        ctx,
                        "CACHE-SENSITIVE-NO-STORE",
                        evidence=f"Cache-Control: {primary.header('cache-control') or '(absent)'}; "
                        f"Pragma: {primary.header('pragma') or '(absent)'}",
                        url=url,
                        detail="Response considered sensitive because it " + " and ".join(reasons) + ".",
                    )
                )
        return findings
