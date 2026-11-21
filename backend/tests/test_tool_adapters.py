"""Passive tool adapters: parsers run against real tool output recorded from a local nginx fixture.

No network and no real tools: the fixtures were captured once inside the Docker stack against a
throwaway container (fixture.test, self-signed certificate, jQuery 1.8.1, cookie without flags).
"""

from __future__ import annotations

import copy
import json
import stat
import sys
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from app.engine.scope_guard import Target
from app.models.audit import AuditRequest
from app.models.finding import Severity
from app.tools.adapters import AdapterContext, AdapterResult, ToolAdapter
from app.tools.adapters import retire, sslyze, testssl, whatweb, zap
from app.tools.adapters.retire import RetireAdapter
from app.tools.adapters.sslyze import SSLyzeAdapter
from app.tools.adapters.testssl import TestSSLAdapter
from app.tools.adapters.whatweb import WhatWebAdapter
from app.tools.adapters.zap import ZapAdapter
from app.tools.merge import merge_findings
from app.checks.base import rule_finding

FIXTURES = Path(__file__).parent / "fixtures" / "tools"


def load(name: str):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def ctx() -> AdapterContext:
    return AdapterContext(target=Target(host="fixture.test"), url="https://fixture.test/", https_ok=True)


def ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- WhatWeb


def test_whatweb_technologies_and_banner(ctx):
    techs, findings = whatweb.parse(load("whatweb.json"), ctx, WhatWebAdapter())
    names = {(t.name, t.version) for t in techs}
    assert ("nginx", "1.30.7") in names and ("JQuery", "1.8.1") in names
    assert not any(t.name in ("IP", "Country", "Title") for t in techs)
    assert ids(findings) == {"DISC-SERVER-VERSION"}
    assert findings[0].sources == ["whatweb"] and findings[0].tool_refs == ["whatweb:HTTPServer"]
    assert findings[0].cvss_score is not None  # mapped onto a built-in rule


# --------------------------------------------------------------------------- SSLyze


def test_sslyze_self_signed_fixture(ctx):
    findings = sslyze.parse(load("sslyze.json"), ctx, SSLyzeAdapter())
    assert ids(findings) == {"TLS-CERT-UNTRUSTED", "TLS-CERT-EXPIRING"}
    untrusted = next(f for f in findings if f.rule_id == "TLS-CERT-UNTRUSTED")
    assert "Mozilla" in untrusted.evidence and untrusted.sources == ["sslyze"]


def test_sslyze_deprecated_protocols_weak_ciphers_and_compression(ctx):
    data = copy.deepcopy(load("sslyze.json"))
    scan = data["server_scan_results"][0]["scan_result"]
    scan["tls_1_0_cipher_suites"]["result"]["is_tls_version_supported"] = True
    scan["tls_1_0_cipher_suites"]["result"]["accepted_cipher_suites"] = [
        {"cipher_suite": {"name": "TLS_RSA_WITH_RC4_128_SHA", "is_anonymous": False, "key_size": 128}}]
    scan["tls_compression"]["result"]["supports_compression"] = True
    findings = sslyze.parse(data, ctx, SSLyzeAdapter())
    assert {"TLS-DEPRECATED-PROTOCOL", "TLS-WEAK-CIPHER", "SSLYZE-COMPRESSION"} <= ids(findings)
    assert "TLS 1.0" in next(f for f in findings if f.rule_id == "TLS-DEPRECATED-PROTOCOL").evidence
    crime = next(f for f in findings if f.rule_id == "SSLYZE-COMPRESSION")
    assert crime.cvss_score is None and crime.cwe == "CWE-310" and crime.owasp == ["A04:2025"]


def test_sslyze_never_requests_vulnerability_probes():
    for probe in ("--heartbleed", "--robot", "--openssl_ccs", "--reneg"):
        assert probe not in sslyze.SCAN_COMMANDS


def test_sslyze_skips_hosts_without_https(ctx):
    ctx.https_ok = False
    assert SSLyzeAdapter().applicable(ctx) == "no HTTPS endpoint"


# --------------------------------------------------------------------------- testssl.sh


def test_testssl_fixture_mapping(ctx):
    findings = testssl.parse(load("testssl.json"), ctx, TestSSLAdapter())
    found = ids(findings)
    assert {"TLS-CERT-UNTRUSTED", "TLS-CERT-HOSTNAME-MISMATCH", "TLS-CERT-EXPIRING"} <= found
    assert {"TESTSSL-CERT-SUBJECTALTNAME", "TESTSSL-CERT-REVOCATION", "TESTSSL-CIPHERLIST-OBSOLETED"} <= found
    assert "TLS-DEPRECATED-PROTOCOL" not in found  # fixture offers TLS 1.2/1.3 only
    assert "TESTSSL-CERT-NOTAFTER" not in found  # duplicate of the expiry finding
    san = next(f for f in findings if f.rule_id == "TESTSSL-CERT-SUBJECTALTNAME")
    assert san.severity is Severity.HIGH and san.cwe == "CWE-295" and "A04:2025" in san.owasp


def test_testssl_deprecated_protocol(ctx):
    data = copy.deepcopy(load("testssl.json"))
    next(e for e in data if e["id"] == "TLS1")["finding"] = "offered (deprecated)"
    findings = testssl.parse(data, ctx, TestSSLAdapter())
    proto = next(f for f in findings if f.rule_id == "TLS-DEPRECATED-PROTOCOL")
    assert proto.evidence == "Server offers: TLS 1.0"


def test_testssl_never_requests_vulnerability_section():
    assert not any(flag in testssl.SECTIONS for flag in ("-U", "--vulnerable", "-H", "--heartbleed"))


# --------------------------------------------------------------------------- Retire.js


def test_retire_parse_maps_to_vulnerable_library(ctx):
    data = load("retire.json")
    file_urls = {data["data"][0]["file"]: "https://fixture.test/js/jquery-1.8.1.min.js"}
    findings = retire.parse(data, ctx, RetireAdapter(), file_urls)
    assert ids(findings) == {"JS-VULNERABLE-LIBRARY"}
    f = findings[0]
    assert "jquery 1.8.1 at https://fixture.test/js/jquery-1.8.1.min.js" in f.evidence and "CVE-2020-7656" in f.evidence
    assert f.tool_refs == ["retire:jquery@1.8.1"] and "Retire.js advisories" in f.description


def _fake_tool(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


async def test_retire_fetches_only_same_host_scripts_and_keeps_filenames(ctx, tmp_path, monkeypatch):
    fixture = json.dumps(load("retire.json"))
    _fake_tool(tmp_path, "retire", (
        "import json, os, sys\n"
        "a = sys.argv; js = a[a.index('--jspath') + 1]; out = a[a.index('--outputpath') + 1]\n"
        "files = [os.path.join(d, f) for d, _, fs in os.walk(js) for f in fs]\n"
        f"data = json.loads({fixture!r})\n"
        "data['data'][0]['file'] = next(f for f in files if f.endswith('jquery-1.8.1.min.js'))\n"
        "json.dump(data, open(out, 'w'))\n"
        "sys.exit(13)"))
    monkeypatch.setenv("PATH", str(tmp_path))
    fetched: list[str] = []

    async def fetch(url: str) -> bytes:
        fetched.append(url)
        return b"/*! jQuery v1.8.1 */"

    ctx.fetch = fetch
    ctx.script_urls = ["https://fixture.test/js/jquery-1.8.1.min.js", "https://cdn.example.net/lib.js"]
    result = await RetireAdapter().run(ctx)
    assert fetched == ["https://fixture.test/js/jquery-1.8.1.min.js"]  # CDN host is out of scope
    assert ids(result.findings) == {"JS-VULNERABLE-LIBRARY"}
    assert result.run.exit_code == 13 and result.run.error is None
    assert result.findings[0].url == "https://fixture.test/" and "fixture.test/js/jquery" in result.findings[0].evidence


async def test_retire_skips_pages_without_scripts(ctx):
    ctx.fetch = lambda url: None
    result = await RetireAdapter().run(ctx)
    assert result.run.error == "skipped: page loads no same-host scripts" and not result.findings


# --------------------------------------------------------------------------- ZAP


def test_zap_alert_mapping(ctx):
    findings = zap.parse(load("zap_alerts.json"), ctx, ZapAdapter())
    found = ids(findings)
    assert {"HDR-CSP-MISSING", "HDR-HSTS-MISSING", "HDR-XFO-MISSING", "HDR-XCTO-MISSING", "CKE-NO-HTTPONLY",
            "CKE-NO-SECURE", "CKE-NO-SAMESITE", "DISC-SERVER-VERSION", "FORM-NO-CSRF-TOKEN"} <= found
    assert "ZAP-10109" not in found  # informational, no CWE
    cache = next(f for f in findings if f.rule_id == "ZAP-10015")
    assert cache.severity is Severity.INFO and cache.cwe == "CWE-525" and cache.cvss_score is None
    assert all(f.sources == ["zap"] for f in findings)


async def test_zap_sends_key_in_header_only_and_cleans_up(ctx, monkeypatch):
    monkeypatch.setenv("WAPTRIX_ZAP_URL", "http://zap.internal:8090")
    monkeypatch.setenv("WAPTRIX_ZAP_API_KEY", "s3cret-test-key")
    calls: list[httpx.Request] = []
    alerts = load("zap_alerts.json")

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        if path.endswith("/accessUrl/"):
            assert request.url.params["followRedirects"] == "false"
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/recordsToScan/"):
            return httpx.Response(200, json={"recordsToScan": "0"})
        if path.endswith("/alerts/"):
            return httpx.Response(200, json={"alerts": alerts})
        if path.endswith("/deleteSiteNode/"):
            return httpx.Response(200, json={"Result": "OK"})
        return httpx.Response(404)

    result = await ZapAdapter(transport=httpx.MockTransport(handler)).run(ctx)
    assert result.run.exit_code == 0 and result.findings
    assert all(r.headers["X-ZAP-API-Key"] == "s3cret-test-key" for r in calls)
    assert not any("s3cret-test-key" in str(r.url) for r in calls)
    assert "s3cret-test-key" not in result.run.model_dump_json()
    assert calls[-1].url.path.endswith("/deleteSiteNode/")
    assert not any("spider" in r.url.path or "ascan" in r.url.path for r in calls)


async def test_zap_unreachable_is_recorded_without_leaking_key(ctx, monkeypatch):
    monkeypatch.setenv("WAPTRIX_ZAP_API_KEY", "s3cret-test-key")

    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    result = await ZapAdapter(transport=httpx.MockTransport(handler)).run(ctx)
    assert result.run.error == "ZAP API error: ConnectError" and not result.findings
    assert "s3cret-test-key" not in result.run.model_dump_json()


# --------------------------------------------------------------------------- merge + request validation


def test_merge_corroborates_existing_rules_and_adds_new_ones(ctx):
    builtin = [rule_finding("HDR-CSP-MISSING", "fixture.test", "https://fixture.test/", "no CSP")]
    tool = WhatWebAdapter()
    incoming = [
        tool.mapped(ctx, "HDR-CSP-MISSING", "x", "csp"),
        tool.mapped(ctx, "JS-VULNERABLE-LIBRARY", "a@1", "a 1"),
        tool.mapped(ctx, "JS-VULNERABLE-LIBRARY", "b@2", "b 2"),
    ]
    merged = merge_findings(builtin, incoming)
    assert [f.rule_id for f in merged] == ["HDR-CSP-MISSING", "JS-VULNERABLE-LIBRARY", "JS-VULNERABLE-LIBRARY"]
    assert merged[0].sources == ["waptrix", "whatweb"] and merged[0].evidence == "no CSP"

    later = RetireAdapter().mapped(ctx, "JS-VULNERABLE-LIBRARY", "a@1", "a 1 again")
    merged = merge_findings(merged, [later])
    libs = [f for f in merged if f.rule_id == "JS-VULNERABLE-LIBRARY"]
    assert len(libs) == 2 and all(f.sources == ["whatweb", "retire"] for f in libs)


def test_request_rejects_active_and_unknown_tools():
    with pytest.raises(ValidationError, match="non-passive"):
        AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1", tools=["nmap"])
    with pytest.raises(ValidationError, match="non-passive"):
        AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1", tools=["sqlmap"])
    req = AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1", tools=["ZAP", "zap", " sslyze "])
    assert req.tools == ["zap", "sslyze"]


# --------------------------------------------------------------------------- auditor integration


class FakeAdapter(ToolAdapter):
    name = "zap"

    def __init__(self):
        self.contexts: list[AdapterContext] = []

    async def execute(self, ctx, workdir):
        self.contexts.append(ctx)
        return AdapterResult(tool=self.name, findings=[
            self.mapped(ctx, "HDR-CSP-MISSING", "10038", "zap csp"),
            self.unmapped(ctx, "90099", "Odd header", Severity.LOW, "firm", 16, "desc", "X-Odd: 1"),
        ])


class BrokenAdapter(ToolAdapter):
    name = "sslyze"

    async def execute(self, ctx, workdir):
        raise RuntimeError("tool exploded")


async def test_auditor_runs_adapters_and_merges(monkeypatch):
    from tests.test_passive_checks import StaticTLS
    from tests.conftest import good_tls

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"Location": f"https://{request.url.host}/"})
        if request.url.path == "/":
            return httpx.Response(200, html='<html><script src="/app.js"></script>'
                                             '<script src="https://cdn.example.net/x.js"></script></html>')
        return httpx.Response(404)

    async def resolver(host):
        return ["93.184.216.34"]

    from app.engine.passive_auditor import PassiveAuditor

    fake = FakeAdapter()
    audit = await PassiveAuditor(
        AuditRequest(subdomains=["shop.example.com"], authorization_ref="ENG-TEST-09"),
        transport=httpx.MockTransport(handler), tls_inspector=StaticTLS(good_tls()), resolver=resolver,
        adapters=[fake, BrokenAdapter()],
    ).run()
    sub = audit.subdomains[0]
    assert fake.contexts[0].script_urls == ["https://shop.example.com/app.js"]
    csp = [f for f in sub.findings if f.rule_id == "HDR-CSP-MISSING"]
    assert len(csp) == 1 and csp[0].sources == ["waptrix", "zap"]
    assert any(f.rule_id == "ZAP-90099" for f in sub.findings)
    assert {r.tool for r in sub.tool_runs} == {"zap", "sslyze"}
    assert next(r for r in sub.tool_runs if r.tool == "sslyze").error == "adapter error: tool exploded"
    assert any(r["rule_id"] == "ZAP-90099" for r in audit.summary.top_rules)


def test_merge_generic_httponly_corroborates_session_variant(ctx):
    builtin = [rule_finding("CKE-SESSION-NO-HTTPONLY", "fixture.test", "https://fixture.test/", "sid")]
    merged = merge_findings(builtin, [ZapAdapter().mapped(ctx, "CKE-NO-HTTPONLY", "10010", "Set-Cookie: sid")])
    assert [f.rule_id for f in merged] == ["CKE-SESSION-NO-HTTPONLY"] and merged[0].sources == ["waptrix", "zap"]
