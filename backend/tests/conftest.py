from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.checks.base import AuditContext  # noqa: E402
from app.engine.fetcher import FetchHop, FetchResult  # noqa: E402
from app.engine.scope_guard import Target  # noqa: E402
from app.models.audit import TLSInfo  # noqa: E402

HOST = "app.example.com"
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def response(
    url: str = f"https://{HOST}/",
    status: int = 200,
    headers: list[tuple[str, str]] | dict[str, str] | None = None,
    body: str = "",
    redirects: list[tuple[str, int, str]] | None = None,
    error: str | None = None,
    content_type: str | None = "text/html; charset=utf-8",
) -> FetchResult:
    """Build a FetchResult as the fetcher would have produced it."""
    if error:
        return FetchResult(url=url, error=error)
    header_list = list(headers.items()) if isinstance(headers, dict) else list(headers or [])
    if content_type and not any(k.lower() == "content-type" for k, _ in header_list):
        header_list.append(("Content-Type", content_type))
    hops = [FetchHop(url=u, status_code=s, headers=[("Location", loc)]) for u, s, loc in (redirects or [])]
    final_url = url if not redirects else redirects[-1][2]
    hops.append(FetchHop(url=final_url, status_code=status, headers=header_list))
    return FetchResult(url=url if not redirects else redirects[0][0], hops=hops, body=body, body_bytes=len(body))


def good_tls(**overrides) -> TLSInfo:
    data = dict(
        host=HOST,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cert_subject=f"commonName={HOST}",
        cert_issuer="commonName=Test CA",
        cert_not_before=NOW - timedelta(days=30),
        cert_not_after=NOW + timedelta(days=200),
        days_to_expiry=200,
        san=[HOST],
        hostname_match=True,
        trusted=True,
        legacy_probe="completed",
    )
    data.update(overrides)
    return TLSInfo(**data)


def context(
    https: FetchResult | None = None,
    http: FetchResult | None = None,
    tls: TLSInfo | None = None,
    robots: FetchResult | None = None,
    security_txt: FetchResult | None = None,
    host: str = HOST,
) -> AuditContext:
    return AuditContext(
        target=Target(host=host),
        https=https,
        http=http,
        tls=tls,
        robots=robots,
        security_txt=security_txt,
        now=NOW,
    )


HARDENED_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


@pytest.fixture
def hardened_https() -> FetchResult:
    return response(headers=dict(HARDENED_HEADERS), body="<html><body><h1>Hi</h1></body></html>")


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}
