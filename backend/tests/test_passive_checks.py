"""Unit tests for scope guard, fetcher and every passive check group, using mocked HTTP responses."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from app.checks.client_forms import ClientFormsCheck, fingerprint_library
from app.checks.cookies import CookieCheck, parse_set_cookie
from app.checks.cors_cache import CorsCacheCheck
from app.checks.disclosure import DisclosureCheck
from app.checks.headers import SecurityHeadersCheck, csp_weaknesses
from app.checks.metadata import MetadataCheck
from app.checks.transport_tls import TransportTLSCheck
from app.engine.fetcher import MAX_BODY_BYTES, Fetcher, hostname_matches
from app.engine.passive_auditor import PassiveAuditor
from app.engine.scope_guard import (
    RateLimiter,
    ScopeError,
    Target,
    build_scope,
    is_restricted_ip,
    normalize_host,
    resolve_and_check,
    validate_authorization_ref,
)
from app.models.audit import AuditRequest
from tests.conftest import HARDENED_HEADERS, HOST, NOW, context, good_tls, response, rule_ids

# --------------------------------------------------------------------------- scope guard


class TestScopeGuard:
    def test_requires_authorization_reference(self):
        with pytest.raises(ScopeError):
            validate_authorization_ref("")
        with pytest.raises(ScopeError):
            validate_authorization_ref("x")
        assert validate_authorization_ref(" ENG-2026-001 ") == "ENG-2026-001"

    @pytest.mark.parametrize(
        ("raw", "host", "port"),
        [
            ("App.Example.COM", "app.example.com", None),
            ("https://app.example.com/login?x=1", "app.example.com", None),
            ("app.example.com.", "app.example.com", None),
            ("app.example.com:8443", "app.example.com", 8443),
            ("http://app.example.com:80/", "app.example.com", None),
            ("bücher.example.com", "xn--bcher-kva.example.com", None),
        ],
    )
    def test_normalize_host(self, raw, host, port):
        target = normalize_host(raw)
        assert (target.host, target.port) == (host, port)

    @pytest.mark.parametrize("raw", ["*.example.com", "localhost", "bad_host!.com", "https://user:pw@x.example.com", ""])
    def test_normalize_rejects_invalid(self, raw):
        with pytest.raises(ValueError):
            normalize_host(raw)

    def test_build_scope_dedupes_and_rejects(self):
        decision = build_scope(
            ["app.example.com", "https://APP.example.com/", "# comment", "api.example.com", "evil.other.net",
             "*.example.com", "10.1.2.3"],
            "ENG-1",
            scope_domains=["example.com"],
        )
        assert [t.host for t in decision.targets] == ["app.example.com", "api.example.com"]
        reasons = {r.input: r.reason for r in decision.rejections}
        assert "outside declared scope" in reasons["evil.other.net"]
        assert "wildcard" in reasons["*.example.com"]
        assert "private" in reasons["10.1.2.3"]

    def test_build_scope_without_valid_targets_fails(self):
        with pytest.raises(ScopeError):
            build_scope(["*.example.com"], "ENG-1")

    @pytest.mark.parametrize(
        ("ip", "restricted"),
        [("10.0.0.1", True), ("127.0.0.1", True), ("169.254.169.254", True), ("100.64.1.1", True),
         ("::1", True), ("::ffff:192.168.1.1", True), ("8.8.8.8", False), ("2606:4700::1111", False)],
    )
    def test_restricted_ips(self, ip, restricted):
        assert is_restricted_ip(ip) is restricted

    async def test_resolution_to_private_address_is_blocked(self):
        async def resolver(host):
            return ["93.184.216.34", "10.0.0.5"]

        with pytest.raises(ScopeError):
            await resolve_and_check("app.example.com", allow_private=False, resolver=resolver)
        assert await resolve_and_check("app.example.com", allow_private=True, resolver=resolver)

    async def test_rate_limiter_spaces_requests(self):
        import time

        limiter = RateLimiter(requests_per_second=20)
        start = time.monotonic()
        for _ in range(4):
            await limiter.acquire("h")
        assert time.monotonic() - start >= 0.14


# --------------------------------------------------------------------------- fetcher


class TestFetcher:
    async def test_only_get_and_on_host_redirects(self):
        seen: list[tuple[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append((request.method, str(request.url)))
            if request.url.path == "/":
                return httpx.Response(302, headers={"Location": "/home"})
            if request.url.path == "/home":
                return httpx.Response(301, headers={"Location": "https://sso.other.example/login"})
            return httpx.Response(200)

        target = Target(host=HOST)
        async with Fetcher(RateLimiter(100), transport=httpx.MockTransport(handler)) as fetcher:
            result = await fetcher.get(target.https_url("/"), target)

        assert all(method == "GET" for method, _ in seen)
        assert [u for _, u in seen] == [f"https://{HOST}/", f"https://{HOST}/home"]
        assert result.stopped_offscope == "https://sso.other.example/login"
        assert result.status_code == 301
        assert len(result.to_observation().redirect_chain) == 1

    async def test_body_is_capped(self):
        big = "a" * (MAX_BODY_BYTES + 5000)
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text=big))
        target = Target(host=HOST)
        async with Fetcher(RateLimiter(100), transport=transport) as fetcher:
            result = await fetcher.get(target.https_url(), target)
        assert result.truncated
        assert result.body_bytes == MAX_BODY_BYTES

    async def test_connection_error_is_captured(self):
        def handler(request):
            raise httpx.ConnectError("refused", request=request)

        target = Target(host=HOST)
        async with Fetcher(RateLimiter(100), transport=httpx.MockTransport(handler)) as fetcher:
            result = await fetcher.get(target.https_url(), target)
        assert not result.ok
        assert "connection failed" in result.error

    async def test_redirect_loop_stops(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(302, headers={"Location": "/"}))
        target = Target(host=HOST)
        async with Fetcher(RateLimiter(1000), transport=transport) as fetcher:
            result = await fetcher.get(target.https_url(), target)
        assert result.error and "too many redirects" in result.error

    def test_hostname_matching(self):
        assert hostname_matches("app.example.com", ["*.example.com"])
        assert not hostname_matches("a.b.example.com", ["*.example.com"])
        assert not hostname_matches("example.com", ["*.example.com"])
        assert hostname_matches("example.com", ["EXAMPLE.com"])


# --------------------------------------------------------------------------- headers


class TestSecurityHeaders:
    def test_hardened_response_is_clean(self, hardened_https):
        assert SecurityHeadersCheck().run(context(https=hardened_https)) == []

    def test_missing_headers(self):
        ctx = context(https=response(body="<html></html>"))
        assert rule_ids(SecurityHeadersCheck().run(ctx)) == {
            "HDR-CSP-MISSING", "HDR-HSTS-MISSING", "HDR-XFO-MISSING", "HDR-XCTO-MISSING",
            "HDR-REFERRER-MISSING", "HDR-PERMISSIONS-MISSING",
        }

    def test_weak_csp_and_short_hsts(self):
        headers = dict(HARDENED_HEADERS)
        headers["Content-Security-Policy"] = "default-src * 'unsafe-inline' 'unsafe-eval'"
        headers["Strict-Transport-Security"] = "max-age=3600"
        findings = SecurityHeadersCheck().run(context(https=response(headers=headers, body="<html></html>")))
        assert rule_ids(findings) == {"HDR-CSP-WEAK", "HDR-HSTS-WEAK"}
        weak = next(f for f in findings if f.rule_id == "HDR-CSP-WEAK")
        assert "unsafe-inline" in weak.description and "unsafe-eval" in weak.description

    def test_csp_nonce_neutralises_unsafe_inline(self):
        assert csp_weaknesses("script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'") == []

    def test_frame_ancestors_satisfies_clickjacking(self):
        headers = {k: v for k, v in HARDENED_HEADERS.items() if k != "X-Frame-Options"}
        findings = SecurityHeadersCheck().run(context(https=response(headers=headers, body="<html></html>")))
        assert "HDR-XFO-MISSING" not in rule_ids(findings)

    def test_report_only_csp_counts_as_missing(self):
        headers = {k: v for k, v in HARDENED_HEADERS.items() if k != "Content-Security-Policy"}
        headers["Content-Security-Policy-Report-Only"] = "default-src 'self'"
        findings = SecurityHeadersCheck().run(context(https=response(headers=headers, body="<html></html>")))
        csp = next(f for f in findings if f.rule_id == "HDR-CSP-MISSING")
        assert "Report-Only" in csp.evidence

    def test_non_html_skips_html_only_headers(self):
        resp = response(headers={"Strict-Transport-Security": "max-age=31536000"}, body='{"a":1}',
                        content_type="application/json")
        assert rule_ids(SecurityHeadersCheck().run(context(https=resp))) == {"HDR-XCTO-MISSING"}


# --------------------------------------------------------------------------- transport / TLS


class TestTransportTLS:
    def test_secure_configuration_is_clean(self, hardened_https):
        http = response(url=f"http://{HOST}/", redirects=[(f"http://{HOST}/", 301, f"https://{HOST}/")],
                        headers=dict(HARDENED_HEADERS), body="<html></html>")
        assert TransportTLSCheck().run(context(https=hardened_https, http=http, tls=good_tls())) == []

    def test_http_only_host(self):
        ctx = context(https=response(error="connection failed: refused"),
                      http=response(url=f"http://{HOST}/", body="<html></html>"))
        assert rule_ids(TransportTLSCheck().run(ctx)) == {"TLS-NO-HTTPS"}

    def test_missing_redirect(self, hardened_https):
        ctx = context(https=hardened_https, http=response(url=f"http://{HOST}/", body="<html></html>"), tls=good_tls())
        assert rule_ids(TransportTLSCheck().run(ctx)) == {"TLS-NO-REDIRECT"}

    def test_bad_certificate_and_protocols(self, hardened_https):
        tls = good_tls(
            protocol="TLSv1.2",
            cipher="ECDHE-RSA-DES-CBC3-SHA",
            cipher_bits=112,
            cert_not_after=NOW - timedelta(days=3),
            days_to_expiry=-3,
            hostname_match=False,
            san=["other.example.net"],
            trusted=False,
            self_signed=True,
            verify_error="self-signed certificate",
            legacy_protocols_accepted=["TLSv1"],
        )
        found = rule_ids(TransportTLSCheck().run(context(https=hardened_https, tls=tls)))
        assert found == {
            "TLS-DEPRECATED-PROTOCOL", "TLS-WEAK-CIPHER", "TLS-CERT-EXPIRED",
            "TLS-CERT-HOSTNAME-MISMATCH", "TLS-CERT-UNTRUSTED",
        }

    def test_untrusted_not_duplicated_for_hostname_mismatch(self, hardened_https):
        tls = good_tls(hostname_match=False, trusted=False, verify_error="Hostname mismatch, certificate is not valid")
        assert rule_ids(TransportTLSCheck().run(context(https=hardened_https, tls=tls))) == {"TLS-CERT-HOSTNAME-MISMATCH"}

    def test_expiring_certificate(self, hardened_https):
        tls = good_tls(cert_not_after=NOW + timedelta(days=9), days_to_expiry=9)
        assert rule_ids(TransportTLSCheck().run(context(https=hardened_https, tls=tls))) == {"TLS-CERT-EXPIRING"}

    def test_mixed_content(self):
        body = """<html><head><script src="http://cdn.x.com/a.js"></script>
        <link rel="stylesheet" href="http://cdn.x.com/a.css"></head>
        <body><img src="http://img.x.com/a.png"><img src="https://ok.x.com/b.png"></body></html>"""
        findings = TransportTLSCheck().run(context(https=response(headers=dict(HARDENED_HEADERS), body=body), tls=good_tls()))
        assert rule_ids(findings) == {"TLS-MIXED-CONTENT-ACTIVE", "TLS-MIXED-CONTENT-PASSIVE"}
        active = next(f for f in findings if f.rule_id == "TLS-MIXED-CONTENT-ACTIVE")
        assert "a.js" in active.evidence and "a.css" in active.evidence


# --------------------------------------------------------------------------- cookies


class TestCookies:
    def test_parse_set_cookie(self):
        cookie = parse_set_cookie("SID=abc; Path=/; Secure; HttpOnly; SameSite=Strict; Domain=.example.com", "https://x/")
        assert cookie.secure and cookie.httponly and cookie.samesite == "strict" and cookie.domain == "example.com"

    def test_hardened_cookie_is_clean(self):
        resp = response(headers=[("Set-Cookie", "__Host-sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")])
        assert CookieCheck().run(context(https=resp)) == []

    def test_insecure_session_cookie(self):
        resp = response(headers=[("Set-Cookie", "PHPSESSID=0123456789abcdef; path=/; domain=.example.com")])
        findings = CookieCheck().run(context(https=resp))
        assert rule_ids(findings) == {"CKE-NO-SECURE", "CKE-SESSION-NO-HTTPONLY", "CKE-NO-SAMESITE", "CKE-BROAD-DOMAIN"}
        assert all("0123456789abcdef" not in f.evidence for f in findings), "cookie values must be redacted"

    def test_samesite_none_without_secure_and_non_session_cookie(self):
        resp = response(headers=[("Set-Cookie", "prefs=dark; Path=/; SameSite=None")])
        assert rule_ids(CookieCheck().run(context(https=resp))) == {
            "CKE-NO-SECURE", "CKE-NO-HTTPONLY", "CKE-SAMESITE-NONE-INSECURE",
        }

    def test_csrf_cookie_may_be_script_readable(self):
        resp = response(headers=[("Set-Cookie", "csrftoken=abc; Path=/; Secure; SameSite=Lax")])
        assert CookieCheck().run(context(https=resp)) == []

    def test_cookies_on_redirect_hops_are_inspected(self):
        resp = response(
            redirects=[(f"https://{HOST}/", 302, f"https://{HOST}/home")],
            headers={"Content-Type": "text/html"},
        )
        resp.hops[0].headers.append(("Set-Cookie", "session=xyz; Secure; HttpOnly"))
        assert rule_ids(CookieCheck().run(context(https=resp))) == {"CKE-NO-SAMESITE"}

    def test_deletion_cookies_are_ignored(self):
        resp = response(headers=[("Set-Cookie", "old=; Max-Age=0; Path=/")])
        assert CookieCheck().run(context(https=resp)) == []


# --------------------------------------------------------------------------- CORS / cache


class TestCorsCache:
    def test_wildcard_with_credentials(self):
        resp = response(headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        assert rule_ids(CorsCacheCheck().run(context(https=resp))) == {"CORS-WILDCARD-CREDENTIALS"}

    @pytest.mark.parametrize(("acao", "rule"), [("null", "CORS-NULL-ORIGIN"), ("*", "CORS-WILDCARD")])
    def test_origin_values(self, acao, rule):
        resp = response(headers={"Access-Control-Allow-Origin": acao})
        assert rule_ids(CorsCacheCheck().run(context(https=resp))) == {rule}

    def test_specific_origin_is_fine(self):
        resp = response(headers={"Access-Control-Allow-Origin": "https://app.example.com",
                                 "Access-Control-Allow-Credentials": "true"})
        assert CorsCacheCheck().run(context(https=resp)) == []

    def test_login_page_cacheable(self):
        resp = response(headers={"Cache-Control": "private, max-age=600"},
                        body='<html><form><input type="password" name="p"></form></html>')
        findings = CorsCacheCheck().run(context(https=resp))
        assert rule_ids(findings) == {"CACHE-SENSITIVE-NO-STORE"}

    def test_no_store_satisfies_cache_rule(self):
        resp = response(headers=[("Cache-Control", "no-store"), ("Set-Cookie", "sessionid=1; Secure; HttpOnly")])
        assert CorsCacheCheck().run(context(https=resp)) == []


# --------------------------------------------------------------------------- disclosure


class TestDisclosure:
    def test_banners(self):
        resp = response(headers={"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.1",
                                 "X-Debug-Token": "a1b2c3"}, body="<html></html>")
        assert rule_ids(DisclosureCheck().run(context(https=resp))) == {
            "DISC-SERVER-VERSION", "DISC-VERSION-HEADER", "DISC-DEBUG-MODE",
        }

    def test_generic_server_banner_not_flagged(self):
        resp = response(headers={"Server": "nginx"}, body="<html></html>")
        assert DisclosureCheck().run(context(https=resp)) == []

    @pytest.mark.parametrize(
        "body",
        [
            "Traceback (most recent call last):\n  File \"/app/x.py\", line 3",
            "java.lang.NullPointerException\n\tat com.acme.Foo.bar(Foo.java:42)",
            "<b>Fatal error</b>:  Uncaught Error in <b>/var/www/a.php</b> on line <b>7</b>",
            "TypeError: x is undefined\n    at handler (/srv/app/index.js:10:5)",
            "goroutine 1 [running]:\nmain.main()",
        ],
    )
    def test_stack_traces(self, body):
        resp = response(status=500, body=body, content_type="text/plain")
        assert "DISC-STACK-TRACE" in rule_ids(DisclosureCheck().run(context(https=resp)))

    def test_django_debug_page(self):
        body = "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings</p>"
        assert "DISC-DEBUG-MODE" in rule_ids(DisclosureCheck().run(context(https=response(body=body))))

    def test_comments_ips_and_emails(self):
        body = """<html><body><!-- TODO: remove hardcoded admin password --><!-- layout v2 -->
        <!--[if lt IE 9]><script src="x.js"></script><![endif]-->
        <p>Backend 192.168.10.4 · version 1.10.0.1 · contact security@example.com · logo@2x.png</p></body></html>"""
        findings = DisclosureCheck().run(context(https=response(body=body)))
        assert rule_ids(findings) == {"DISC-HTML-COMMENTS", "DISC-PRIVATE-IP", "DISC-EMAIL"}
        by_rule = {f.rule_id: f for f in findings}
        assert "layout v2" not in by_rule["DISC-HTML-COMMENTS"].evidence
        assert by_rule["DISC-PRIVATE-IP"].evidence.endswith("192.168.10.4")
        assert "logo@2x.png" not in by_rule["DISC-EMAIL"].evidence


# --------------------------------------------------------------------------- client forms / SRI / libraries


class TestClientForms:
    def test_password_form_over_http(self):
        body = '<html><form method="post" action="/login"><input type="hidden" name="csrf_token" value="x">' \
               '<input type="password" name="pw" autocomplete="current-password"></form></html>'
        ctx = context(https=response(error="refused"), http=response(url=f"http://{HOST}/", body=body))
        assert rule_ids(ClientFormsCheck().run(ctx)) == {"FORM-PASSWORD-OVER-HTTP"}

    def test_https_page_with_http_action_and_no_csrf(self):
        body = '<html><form method="POST" action="http://app.example.com/subscribe"><input name="email"></form>' \
               '<form method="post" action="/x"><input type="password" name="pw"></form></html>'
        found = rule_ids(ClientFormsCheck().run(context(https=response(body=body))))
        assert found == {"FORM-INSECURE-ACTION", "FORM-NO-CSRF-TOKEN", "FORM-PASSWORD-AUTOCOMPLETE"}

    def test_get_forms_do_not_need_csrf(self):
        body = '<html><form action="/search"><input name="q"></form></html>'
        assert ClientFormsCheck().run(context(https=response(body=body))) == []

    def test_sri_rules_ignore_first_party(self):
        body = """<html><head>
        <script src="/static/app.js"></script>
        <script src="https://static.example.com/vendor.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0" integrity="sha384-abc" crossorigin="anonymous"></script>
        <script src="https://cdn.thirdparty.net/widget.js"></script>
        <link rel="stylesheet" href="https://fonts.thirdparty.net/x.css">
        </head></html>"""
        findings = ClientFormsCheck().run(context(https=response(body=body)))
        assert rule_ids(findings) == {"SRI-MISSING-SCRIPT", "SRI-MISSING-STYLESHEET"}
        script = next(f for f in findings if f.rule_id == "SRI-MISSING-SCRIPT")
        assert script.evidence == "https://cdn.thirdparty.net/widget.js"

    @pytest.mark.parametrize(
        ("url", "library", "version"),
        [
            ("https://code.jquery.com/jquery-1.12.4.min.js", "jQuery", "1.12.4"),
            ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js", "jQuery", "3.4.1"),
            ("https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js", "Lodash", "4.17.15"),
            ("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.1.0/js/bootstrap.min.js", "Bootstrap", "4.1.0"),
            ("/js/angular-1.8.2.min.js", "AngularJS", "1.8.2"),
        ],
    )
    def test_vulnerable_library_fingerprints(self, url, library, version):
        hits = fingerprint_library(url)
        assert hits and hits[0][0] == library and hits[0][1] == version

    @pytest.mark.parametrize(
        "url",
        [
            "https://code.jquery.com/jquery-3.7.1.min.js",
            "https://code.jquery.com/ui/1.13.2/jquery-ui.min.js",
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js",
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5/jquery.min.js",
        ],
    )
    def test_patched_libraries_not_flagged(self, url):
        assert fingerprint_library(url) == []


# --------------------------------------------------------------------------- metadata


class TestMetadata:
    def _ctx(self, security_body=None, security_status=200, robots_body=None, ctype="text/plain"):
        sec = response(url=f"https://{HOST}/.well-known/security.txt", status=security_status,
                       body=security_body or "", content_type=ctype)
        robots = response(url=f"https://{HOST}/robots.txt", body=robots_body or "", content_type="text/plain") \
            if robots_body is not None else None
        return context(https=response(body="<html></html>"), security_txt=sec, robots=robots)

    def test_valid_security_txt(self):
        body = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
        assert MetadataCheck().run(self._ctx(body)) == []

    def test_missing_security_txt_and_soft_404(self):
        assert rule_ids(MetadataCheck().run(self._ctx("nope", security_status=404))) == {"META-SECURITY-TXT-MISSING"}
        soft_404 = self._ctx("<!doctype html><html>Home</html>", ctype="text/html")
        assert rule_ids(MetadataCheck().run(soft_404)) == {"META-SECURITY-TXT-MISSING"}

    def test_expired_security_txt(self):
        body = "Contact: mailto:security@example.com\nExpires: 2025-01-01T00:00:00Z\n"
        findings = MetadataCheck().run(self._ctx(body))
        assert rule_ids(findings) == {"META-SECURITY-TXT-INVALID"}
        assert "expired" in findings[0].description

    def test_robots_sensitive_paths(self):
        valid = "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\n"
        robots = "User-agent: *\nDisallow: /admin/\nDisallow: /images/\nDisallow: /backup.sql # old\n"
        findings = MetadataCheck().run(self._ctx(valid, robots_body=robots))
        assert rule_ids(findings) == {"META-ROBOTS-SENSITIVE"}
        assert "/admin/" in findings[0].evidence and "/images/" not in findings[0].evidence


# --------------------------------------------------------------------------- end-to-end auditor


class StaticTLS:
    def __init__(self, info):
        self.info = info

    async def inspect(self, target):
        return self.info.model_copy(update={"host": target.host})


async def test_auditor_end_to_end_with_mocked_http():
    requests_seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request.method)
        if request.url.host == "down.example.com":
            raise httpx.ConnectError("refused", request=request)
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"Location": f"https://{request.url.host}{request.url.path}"})
        if request.url.path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:s@example.com\nExpires: 2099-01-01T00:00:00Z\n",
                                  headers={"Content-Type": "text/plain"})
        if request.url.path == "/robots.txt":
            return httpx.Response(404, text="")
        return httpx.Response(200, html="<html><body>ok</body></html>", headers=dict(HARDENED_HEADERS))

    async def resolver(host):
        return ["93.184.216.34"]

    request = AuditRequest(subdomains=["good.example.com", "down.example.com", "not valid"],
                           authorization_ref="ENG-TEST-01", requests_per_second=10)
    progress: list[tuple[int, int]] = []
    audit = await PassiveAuditor(
        request,
        transport=httpx.MockTransport(handler),
        tls_inspector=StaticTLS(good_tls()),
        resolver=resolver,
        progress=lambda d, t, c: progress.append((d, t)),
    ).run()

    assert set(requests_seen) == {"GET"}
    by_host = {s.subdomain: s for s in audit.subdomains}
    good, down = by_host["good.example.com"], by_host["down.example.com"]
    assert good.reachable and good.findings == [] and good.score == 100 and good.grade == "A"
    assert good.https_redirect is True
    assert not down.reachable and down.score is None and down.grade == "N/A"
    assert all(c.status.value == "manual_review" for c in down.categories)
    assert [r.input for r in audit.scope_rejections] == ["not valid"]
    assert audit.summary.overall_score == 100
    assert progress[-1] == (2, 2)


async def test_auditor_skips_hosts_resolving_to_private_ranges():
    async def resolver(host):
        return ["10.0.0.7"]

    transport = httpx.MockTransport(lambda r: pytest.fail("no request may be sent to a private address"))
    audit = await PassiveAuditor(
        AuditRequest(subdomains=["intranet.example.com"], authorization_ref="ENG-TEST-02"),
        transport=transport,
        tls_inspector=StaticTLS(good_tls()),
        resolver=resolver,
    ).run()
    result = audit.subdomains[0]
    assert not result.reachable and "scope guard" in result.error
