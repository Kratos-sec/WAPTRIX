"""Passive review of /robots.txt and /.well-known/security.txt (RFC 9116).

Paths listed in robots.txt are reported but never requested.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from app.checks.base import AuditContext, PassiveCheck
from app.engine.fetcher import FetchResult
from app.models.finding import PassiveFinding

SENSITIVE_PATH = re.compile(
    r"(admin|administrator|backup|\.bak|config|conf\b|private|internal|secret|staging|/dev\b|/test|debug|"
    r"/old\b|/tmp\b|/db\b|\.sql|\.git|\.env|\.svn|phpmyadmin|wp-admin|cgi-bin|/logs?\b|console|actuator|"
    r"swagger|graphql|/api/internal|dump|export)",
    re.IGNORECASE,
)


def _is_plain_text(response: FetchResult) -> bool:
    """Reject soft-404s where the server returns an HTML page for any path."""
    if response.status_code != 200 or not response.body.strip():
        return False
    if "html" in response.content_type:
        return False
    return not response.body.lstrip()[:200].lower().startswith(("<!doctype", "<html", "<head", "<body"))


def parse_security_txt(body: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields


def parse_expires(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def sensitive_disallows(body: str) -> list[str]:
    entries: list[str] = []
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        key, _, value = line.partition(":")
        if key.strip().lower() == "disallow" and value.strip() and SENSITIVE_PATH.search(value):
            entries.append(value.strip())
    return list(dict.fromkeys(entries))


class MetadataCheck(PassiveCheck):
    name = "metadata"
    rule_ids = ("META-SECURITY-TXT-MISSING", "META-SECURITY-TXT-INVALID", "META-ROBOTS-SENSITIVE")

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        if ctx.primary is None:
            return []
        findings: list[PassiveFinding] = []
        findings.extend(self._security_txt(ctx))
        findings.extend(self._robots(ctx))
        return findings

    def _security_txt(self, ctx: AuditContext) -> list[PassiveFinding]:
        response = ctx.security_txt
        if response is None:
            return []
        url = response.url
        if not response.ok or not _is_plain_text(response):
            status = response.status_code if response.ok else response.error
            return [
                self.finding(
                    ctx,
                    "META-SECURITY-TXT-MISSING",
                    evidence=f"GET {url} -> {status} ({response.content_type or 'no content-type'})",
                    url=url,
                )
            ]
        fields = parse_security_txt(response.body)
        problems: list[str] = []
        if not fields.get("contact"):
            problems.append("missing required Contact field")
        expires_values = fields.get("expires", [])
        if not expires_values:
            problems.append("missing required Expires field")
        else:
            expires = parse_expires(expires_values[0])
            if expires is None:
                problems.append(f"unparseable Expires value '{expires_values[0]}'")
            elif expires < ctx.now:
                problems.append(f"expired on {expires.date().isoformat()}")
        if problems:
            return [
                self.finding(
                    ctx,
                    "META-SECURITY-TXT-INVALID",
                    evidence="\n".join(response.body.strip().splitlines()[:10]),
                    url=url,
                    detail="Problems: " + "; ".join(problems) + ".",
                )
            ]
        return []

    def _robots(self, ctx: AuditContext) -> list[PassiveFinding]:
        response = ctx.robots
        if response is None or not response.ok or not _is_plain_text(response):
            return []
        entries = sensitive_disallows(response.body)
        if not entries:
            return []
        return [
            self.finding(
                ctx,
                "META-ROBOTS-SENSITIVE",
                evidence="\n".join(f"Disallow: {e}" for e in entries[:15]),
                url=response.url,
                detail=f"{len(entries)} sensitive-looking path(s) advertised.",
            )
        ]
