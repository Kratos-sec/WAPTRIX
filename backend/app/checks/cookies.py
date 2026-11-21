"""Cookie hygiene checks: Secure, HttpOnly, SameSite and overly broad Domain scoping."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.checks.base import AuditContext, PassiveCheck
from app.models.finding import PassiveFinding

SESSION_NAME = re.compile(
    r"(sess|sid$|^sid|auth|token|jwt|login|remember|identity|connect\.sid|phpsessid|jsessionid|"
    r"asp\.net_sessionid|aspxauth|laravel_session|_session$|refresh)",
    re.IGNORECASE,
)
# Double-submit CSRF cookies must be readable by JavaScript, so HttpOnly is not expected on them.
JS_READABLE_BY_DESIGN = re.compile(r"(csrf|xsrf)", re.IGNORECASE)


@dataclass
class SetCookie:
    name: str
    value: str
    raw: str
    response_url: str
    attributes: dict[str, str] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)

    @property
    def secure(self) -> bool:
        return "secure" in self.flags

    @property
    def httponly(self) -> bool:
        return "httponly" in self.flags

    @property
    def samesite(self) -> str | None:
        value = self.attributes.get("samesite")
        return value.lower() if value else None

    @property
    def domain(self) -> str | None:
        value = self.attributes.get("domain")
        return value.strip().lstrip(".").lower() if value else None

    @property
    def is_session_like(self) -> bool:
        return bool(SESSION_NAME.search(self.name)) and not JS_READABLE_BY_DESIGN.search(self.name)

    @property
    def is_deletion(self) -> bool:
        max_age = self.attributes.get("max-age")
        if max_age is not None and max_age.strip().lstrip("-").isdigit() and int(max_age) <= 0:
            return True
        expires = self.attributes.get("expires", "")
        return "1970" in expires


def parse_set_cookie(header: str, response_url: str) -> SetCookie | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    name = name.strip()
    if not name:
        return None
    cookie = SetCookie(name=name, value=value.strip(), raw=header.strip(), response_url=response_url)
    for attr in parts[1:]:
        if not attr:
            continue
        key, sep, val = attr.partition("=")
        key = key.strip().lower()
        if sep:
            cookie.attributes[key] = val.strip()
        else:
            cookie.flags.add(key)
    return cookie


def collect_cookies(ctx: AuditContext) -> list[SetCookie]:
    cookies: dict[tuple[str, str, str], SetCookie] = {}
    for response in ctx.responses():
        for hop in response.hops:
            for header in hop.header_all("set-cookie"):
                cookie = parse_set_cookie(header, hop.url)
                if cookie is None or cookie.is_deletion:
                    continue
                key = (cookie.name, cookie.domain or "", cookie.attributes.get("path", "/"))
                # Prefer the instance delivered over HTTPS when the same cookie appears twice.
                if key not in cookies or hop.url.startswith("https://"):
                    cookies[key] = cookie
    return list(cookies.values())


def redact(raw: str, cookie: SetCookie) -> str:
    """Never store live session values in reports."""
    if not cookie.value:
        return raw
    shown = cookie.value[:4] + "…[redacted]" if len(cookie.value) > 4 else "[redacted]"
    return raw.replace(f"{cookie.name}={cookie.value}", f"{cookie.name}={shown}", 1)


class CookieCheck(PassiveCheck):
    name = "cookies"
    rule_ids = (
        "CKE-NO-SECURE",
        "CKE-SESSION-NO-HTTPONLY",
        "CKE-NO-HTTPONLY",
        "CKE-NO-SAMESITE",
        "CKE-SAMESITE-NONE-INSECURE",
        "CKE-BROAD-DOMAIN",
    )

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        host = ctx.target.host
        for cookie in collect_cookies(ctx):
            evidence = f"Set-Cookie: {redact(cookie.raw, cookie)}"
            url = cookie.response_url
            if not cookie.secure:
                findings.append(self.finding(ctx, "CKE-NO-SECURE", evidence=evidence, url=url))
            if not cookie.httponly and not JS_READABLE_BY_DESIGN.search(cookie.name):
                rule = "CKE-SESSION-NO-HTTPONLY" if cookie.is_session_like else "CKE-NO-HTTPONLY"
                findings.append(self.finding(ctx, rule, evidence=evidence, url=url))
            samesite = cookie.samesite
            if samesite is None:
                findings.append(self.finding(ctx, "CKE-NO-SAMESITE", evidence=evidence, url=url))
            elif samesite == "none" and not cookie.secure:
                findings.append(self.finding(ctx, "CKE-SAMESITE-NONE-INSECURE", evidence=evidence, url=url))
            domain = cookie.domain
            if domain and domain != host and host.endswith("." + domain):
                findings.append(
                    self.finding(
                        ctx,
                        "CKE-BROAD-DOMAIN",
                        evidence=evidence,
                        url=url,
                        detail=f"Cookie '{cookie.name}' is sent to every host under '{domain}', not only '{host}'.",
                    )
                )
        return findings
