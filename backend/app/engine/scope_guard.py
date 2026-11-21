"""Scope enforcement: authorization reference, host normalization, private-IP protection, rate limiting."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.models.audit import ScopeRejection

MAX_SUBDOMAINS = 500
AUTH_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{2,63}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

Resolver = Callable[[str], Awaitable[list[str]]]


class ScopeError(ValueError):
    """Raised when an audit request violates scope rules as a whole."""


@dataclass(frozen=True)
class Target:
    """A normalized, in-scope audit target."""

    host: str
    port: int | None = None

    @property
    def display(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host

    def https_url(self, path: str = "/") -> str:
        port = f":{self.port}" if self.port and self.port != 443 else ""
        return f"https://{self.host}{port}{path}"

    def http_url(self, path: str = "/") -> str:
        # A custom port is only meaningful for one scheme; HTTP probe uses the default port.
        return f"http://{self.host}{path}"

    @property
    def tls_port(self) -> int:
        return self.port or 443


@dataclass
class ScopeDecision:
    targets: list[Target] = field(default_factory=list)
    rejections: list[ScopeRejection] = field(default_factory=list)


def validate_authorization_ref(ref: str) -> str:
    ref = (ref or "").strip()
    if not AUTH_REF_PATTERN.match(ref):
        raise ScopeError(
            "authorization_ref is required: 3-64 characters (letters, digits, . _ : / # -), "
            "e.g. 'ENG-2026-001'. Only audit systems you are explicitly authorized to test."
        )
    return ref


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_restricted_ip(address: str) -> bool:
    """True for loopback, private, link-local, multicast, reserved and unspecified addresses."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"))
    )


def normalize_host(raw: str) -> Target:
    """Normalize user input (bare host, host:port or URL) into a Target. Raises ValueError."""
    value = raw.strip()
    if not value:
        raise ValueError("empty entry")
    if "*" in value:
        raise ValueError("wildcards are not allowed; list each subdomain explicitly")
    if "://" not in value:
        value = "//" + value
    parts = urlsplit(value)
    if parts.username or parts.password:
        raise ValueError("credentials in target URLs are not allowed")
    host = (parts.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise ValueError("no hostname found")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    if port in (443, 80):
        port = None

    if _is_ip(host):
        return Target(host=host, port=port)

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized hostname") from exc
    if len(ascii_host) > 253:
        raise ValueError("hostname too long")
    labels = ascii_host.split(".")
    if len(labels) < 2:
        raise ValueError("hostname must be fully qualified (e.g. app.example.com)")
    if not all(_LABEL.match(label) for label in labels):
        raise ValueError("hostname contains invalid characters")
    if labels[-1].isdigit():
        raise ValueError("invalid top-level domain")
    return Target(host=ascii_host, port=port)


def _in_scope_domains(host: str, scope_domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in scope_domains)


def build_scope(
    subdomains: list[str],
    authorization_ref: str,
    scope_domains: list[str] | None = None,
    allow_private: bool = False,
) -> ScopeDecision:
    """Validate the engagement and return de-duplicated in-scope targets plus rejections."""
    validate_authorization_ref(authorization_ref)
    if len(subdomains) > MAX_SUBDOMAINS:
        raise ScopeError(f"too many targets ({len(subdomains)}); the maximum per audit is {MAX_SUBDOMAINS}")

    normalized_scope: list[str] = []
    for domain in scope_domains or []:
        try:
            normalized_scope.append(normalize_host(domain).host)
        except ValueError as exc:
            raise ScopeError(f"invalid scope domain {domain!r}: {exc}") from exc

    decision = ScopeDecision()
    seen: set[Target] = set()
    for raw in subdomains:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        try:
            target = normalize_host(raw)
        except ValueError as exc:
            decision.rejections.append(ScopeRejection(input=raw.strip(), reason=str(exc)))
            continue
        if _is_ip(target.host) and is_restricted_ip(target.host) and not allow_private:
            decision.rejections.append(
                ScopeRejection(input=raw.strip(), reason="private/reserved IP address (enable allow_private)")
            )
            continue
        if normalized_scope and not _in_scope_domains(target.host, normalized_scope):
            decision.rejections.append(
                ScopeRejection(input=raw.strip(), reason="outside declared scope domains")
            )
            continue
        if target in seen:
            continue
        seen.add(target)
        decision.targets.append(target)

    if not decision.targets:
        raise ScopeError("no valid in-scope targets after normalization")
    return decision


async def system_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


async def resolve_and_check(host: str, allow_private: bool, resolver: Resolver = system_resolver) -> list[str]:
    """Resolve a hostname and refuse to continue if it points at restricted address space.

    Raises ScopeError on restricted addresses and OSError on resolution failure.
    """
    if _is_ip(host):
        addresses = [host]
    else:
        addresses = await resolver(host)
    if not addresses:
        raise OSError(f"{host} did not resolve")
    if not allow_private:
        restricted = [a for a in addresses if is_restricted_ip(a)]
        if restricted:
            raise ScopeError(f"{host} resolves to restricted address(es) {', '.join(restricted)}; skipped")
    return addresses


def is_same_target(url: str, target: Target) -> bool:
    """Only redirects that stay on the audited host are followed (never off-scope)."""
    host = (urlsplit(url).hostname or "").rstrip(".").lower()
    return host == target.host


class RateLimiter:
    """Per-host minimum-interval limiter shared by HTTP requests and TLS handshakes."""

    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        self.interval = 1.0 / requests_per_second
        self._next_slot: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def acquire(self, host: str) -> None:
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            slot = self._next_slot.get(host, now)
            wait = slot - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._next_slot[host] = max(now, slot) + self.interval
