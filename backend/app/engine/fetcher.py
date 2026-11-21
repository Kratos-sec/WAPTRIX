"""Read-only HTTP GET fetcher and TLS handshake inspector.

Only safe, idempotent GET requests and standard TLS handshakes are performed. No payloads,
no parameter tampering, no request methods other than GET. Redirects are followed manually and
only while they stay on the audited host.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import certifi
import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.engine.scope_guard import RateLimiter, Target, is_same_target
from app.models.audit import HttpObservation, RedirectHop, TLSInfo

USER_AGENT = "WAPTrix-Passive/1.0 (+authorized passive security audit; read-only)"
MAX_BODY_BYTES = 1_500_000
MAX_REDIRECTS = 5
_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class FetchHop:
    url: str
    status_code: int
    headers: list[tuple[str, str]]

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for key, value in self.headers:
            if key.lower() == lname:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [value for key, value in self.headers if key.lower() == lname]


@dataclass
class FetchResult:
    """Internal (non-serialized) result of one GET including body and all redirect hops."""

    url: str
    hops: list[FetchHop] = field(default_factory=list)
    body: str = ""
    body_bytes: int = 0
    truncated: bool = False
    elapsed_ms: int = 0
    error: str | None = None
    stopped_offscope: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.hops)

    @property
    def final(self) -> FetchHop | None:
        return self.hops[-1] if self.hops else None

    @property
    def final_url(self) -> str | None:
        return self.final.url if self.final else None

    @property
    def status_code(self) -> int | None:
        return self.final.status_code if self.final else None

    def header(self, name: str) -> str | None:
        return self.final.header(name) if self.final else None

    def header_all(self, name: str) -> list[str]:
        return self.final.header_all(name) if self.final else []

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").lower()

    @property
    def is_html(self) -> bool:
        ctype = self.content_type
        if "html" in ctype:
            return True
        return not ctype and self.body.lstrip()[:15].lower().startswith(("<!doctype html", "<html"))

    def to_observation(self) -> HttpObservation:
        headers: dict[str, str] = {}
        if self.final:
            for key, value in self.final.headers:
                lk = key.lower()
                headers[lk] = f"{headers[lk]}\n{value}" if lk in headers else value
        chain = [
            RedirectHop(url=h.url, status_code=h.status_code, location=h.header("location"))
            for h in self.hops[:-1]
        ]
        return HttpObservation(
            url=self.url,
            final_url=self.final_url,
            status_code=self.status_code,
            headers=headers,
            redirect_chain=chain,
            elapsed_ms=self.elapsed_ms,
            body_bytes=self.body_bytes,
            error=self.error,
        )


class Fetcher:
    """Async read-only GET client with per-host rate limiting and on-scope redirect following."""

    def __init__(
        self,
        rate_limiter: RateLimiter,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.rate_limiter = rate_limiter
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            # Certificate trust is evaluated separately by the TLS inspector so that content on hosts
            # with broken certificates can still be passively reviewed.
            verify=False,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en",
            },
            transport=transport,
        )

    async def __aenter__(self) -> "Fetcher":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, target: Target, follow: bool = True) -> FetchResult:
        result = FetchResult(url=url)
        started = time.monotonic()
        current = url
        try:
            for _ in range(MAX_REDIRECTS + 1):
                await self.rate_limiter.acquire(target.host)
                request = self._client.build_request("GET", current)
                response = await self._client.send(request, stream=True)
                try:
                    hop = FetchHop(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=list(response.headers.multi_items()),
                    )
                    result.hops.append(hop)
                    location = response.headers.get("location")
                    if follow and response.status_code in _REDIRECT_CODES and location:
                        next_url = str(response.url.join(location))
                        if not is_same_target(next_url, target):
                            result.stopped_offscope = next_url
                            await self._read_body(response, result)
                            break
                        current = next_url
                        continue
                    await self._read_body(response, result)
                    break
                finally:
                    await response.aclose()
            else:
                result.error = f"too many redirects (>{MAX_REDIRECTS})"
        except httpx.TimeoutException:
            result.error = "timeout"
        except httpx.ConnectError as exc:
            result.error = f"connection failed: {_short(exc)}"
        except httpx.HTTPError as exc:
            result.error = f"http error: {_short(exc)}"
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result

    @staticmethod
    async def _read_body(response: httpx.Response, result: FetchResult) -> None:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            remaining = MAX_BODY_BYTES - size
            if remaining <= 0:
                result.truncated = True
                break
            piece = chunk[:remaining]
            chunks.append(piece)
            size += len(piece)
            if len(chunk) > remaining:
                result.truncated = True
                break
        raw = b"".join(chunks)
        result.body_bytes = size
        encoding = response.charset_encoding or "utf-8"
        try:
            result.body = raw.decode(encoding, errors="replace")
        except LookupError:
            result.body = raw.decode("utf-8", errors="replace")


def _short(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    return text[:200]


# --------------------------------------------------------------------------- TLS inspection


def _name_to_str(name: x509.Name) -> str:
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)  # noqa: SLF001


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        pattern = name.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            if host.endswith(suffix) and "." not in host[: -len(suffix)] and host[: -len(suffix)]:
                return True
    return False


def parse_certificate(der: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        san = []
    cns = [str(a.value) for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    return {
        "cert_subject": _name_to_str(cert.subject),
        "cert_issuer": _name_to_str(cert.issuer),
        "cert_serial": format(cert.serial_number, "x"),
        "cert_not_before": not_before,
        "cert_not_after": not_after,
        "days_to_expiry": (not_after - now).days,
        "san": san,
        "self_signed": cert.issuer == cert.subject,
        # RFC 6125: CN is only consulted when no DNS SAN is present.
        "hostname_match": hostname_matches(host, san if san else cns),
    }


class TLSInspector:
    """Performs standard TLS handshakes (no data sent) to observe protocol, cipher and certificate."""

    def __init__(self, rate_limiter: RateLimiter, timeout: float = 10.0, probe_legacy: bool = True) -> None:
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.probe_legacy = probe_legacy

    async def _handshake(self, target: Target, context: ssl.SSLContext) -> ssl.SSLObject:
        await self.rate_limiter.acquire(target.host)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.tls_port, ssl=context, server_hostname=target.host),
            timeout=self.timeout,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise ssl.SSLError("no TLS session established")
            return ssl_object
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (OSError, asyncio.TimeoutError, ssl.SSLError):
                pass

    async def inspect(self, target: Target) -> TLSInfo:
        info = TLSInfo(host=target.host, port=target.tls_port)

        # 1) Observation handshake: accept any certificate so it can be analysed.
        observe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        observe.check_hostname = False
        observe.verify_mode = ssl.CERT_NONE
        try:
            ssl_object = await self._handshake(target, observe)
            info.protocol = ssl_object.version()
            cipher = ssl_object.cipher()
            if cipher:
                info.cipher, _, info.cipher_bits = cipher[0], cipher[1], cipher[2]
            der = ssl_object.getpeercert(binary_form=True)
            if der:
                for key, value in parse_certificate(der, target.host).items():
                    setattr(info, key, value)
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
            info.error = f"TLS handshake failed: {_short(exc)}"
            return info

        # 2) Validation handshake against the public trust store.
        verify = ssl.create_default_context(cafile=certifi.where())
        try:
            await self._handshake(target, verify)
            info.trusted = True
        except ssl.SSLCertVerificationError as exc:
            info.trusted = False
            info.verify_error = exc.verify_message or _short(exc)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            info.trusted = None
            info.verify_error = f"validation handshake inconclusive: {_short(exc)}"

        # 3) Legacy protocol probe: a normal ClientHello capped at TLS 1.1.
        if self.probe_legacy:
            await self._probe_legacy(target, info)
        return info

    async def _probe_legacy(self, target: Target, info: TLSInfo) -> None:
        try:
            legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy.check_hostname = False
            legacy.verify_mode = ssl.CERT_NONE
            legacy.minimum_version = ssl.TLSVersion.TLSv1
            legacy.maximum_version = ssl.TLSVersion.TLSv1_1
            legacy.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError, AttributeError):
            info.legacy_probe = "unsupported_by_client"
            return
        try:
            ssl_object = await self._handshake(target, legacy)
            version = ssl_object.version()
            if version and version not in info.legacy_protocols_accepted:
                info.legacy_protocols_accepted.append(version)
            info.legacy_probe = "completed"
        except ssl.SSLError as exc:
            reason = (getattr(exc, "reason", "") or "").upper()
            # Client-side refusal (OpenSSL built without legacy protocols) is not a server verdict.
            if "NO_PROTOCOLS_AVAILABLE" in reason or "NO_CIPHERS_AVAILABLE" in reason:
                info.legacy_probe = "unsupported_by_client"
            else:
                info.legacy_probe = "completed"
        except (OSError, asyncio.TimeoutError):
            info.legacy_probe = "completed"
