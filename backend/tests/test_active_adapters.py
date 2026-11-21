"""Active tool adapters: parsers run against synthetic tool output, plus active-mode gating.

No network and no real tools — the fixtures are hand-built representative outputs. Active scanning is an
opt-in: these tests pin the gating rules (explicit opt-in + declared scope) that keep it off by default.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.engine.scope_guard import Target
from app.models.audit import AuditRequest
from app.models.finding import Confidence, Severity
from app.tools.adapters import ACTIVE_ADAPTERS, PASSIVE_ADAPTERS, AdapterContext
from app.tools.adapters import nikto, nmap, nuclei, sqlmap, wapiti
from app.tools.adapters.nikto import NiktoAdapter
from app.tools.adapters.nmap import NmapAdapter
from app.tools.adapters.nuclei import NucleiAdapter
from app.tools.adapters.sqlmap import SqlmapAdapter
from app.tools.adapters.wapiti import WapitiAdapter


@pytest.fixture
def ctx() -> AdapterContext:
    return AdapterContext(target=Target(host="fixture.test"), url="https://fixture.test/", https_ok=True)


def ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- Nmap

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="81"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_open_ports_and_version(ctx):
    findings = nmap.parse(NMAP_XML, ctx, NmapAdapter())
    assert ids(findings) == {"NMAP-TCP-22", "NMAP-TCP-80"}  # closed port skipped
    ssh = next(f for f in findings if f.rule_id == "NMAP-TCP-22")
    assert ssh.severity is Severity.INFO and ssh.cwe == "" and "22/tcp open ssh" in ssh.evidence
    http = next(f for f in findings if f.rule_id == "NMAP-TCP-80")
    assert http.severity is Severity.LOW and http.cwe == "CWE-200" and "nginx 1.18.0" in http.evidence


def test_nmap_bad_xml_is_safe(ctx):
    assert nmap.parse("not xml at all", ctx, NmapAdapter()) == []


# --------------------------------------------------------------------------- Nuclei

NUCLEI_RECORDS = [
    {"template-id": "tls-version", "type": "ssl", "matched-at": "fixture.test:443",
     "info": {"name": "TLS Version", "severity": "info"}},
    {"template-id": "CVE-2021-0000", "type": "http", "matched-at": "https://fixture.test/x",
     "info": {"name": "Example RCE", "severity": "critical", "reference": ["https://nvd.nist.gov/x"],
              "classification": {"cve-id": ["CVE-2021-0000"], "cwe-id": ["CWE-77"]}},
     "extracted-results": ["root:x:0:0"]},
    {"template-id": "CVE-2021-0000", "type": "http", "matched-at": "https://fixture.test/x",
     "info": {"name": "Example RCE", "severity": "critical"}},  # duplicate, dropped
]


def test_nuclei_maps_severity_cwe_and_dedupes(ctx):
    findings = nuclei.parse(NUCLEI_RECORDS, ctx, NucleiAdapter())
    assert ids(findings) == {"NUCLEI-TLS-VERSION", "NUCLEI-CVE-2021-0000"}
    rce = next(f for f in findings if f.rule_id == "NUCLEI-CVE-2021-0000")
    assert rce.severity is Severity.CRITICAL and rce.cwe == "CWE-77"
    assert rce.url == "https://fixture.test/x" and "root:x:0:0" in rce.evidence
    assert "CVE-2021-0000" in rce.description and rce.references == ["https://nvd.nist.gov/x"]


# --------------------------------------------------------------------------- Nikto

NIKTO_JSON = {"host": "fixture.test", "vulnerabilities": [
    {"id": "999103", "method": "GET", "url": "/admin/", "msg": "Admin login page found"},
    {"id": "999104", "method": "GET", "url": "/", "msg": "The anti-clickjacking X-Frame-Options header is not present"},
    {"id": "999103", "method": "GET", "url": "/admin/", "msg": "duplicate id, dropped"},
]}


def test_nikto_parses_vulns_and_dedupes(ctx):
    findings = nikto.parse(NIKTO_JSON, ctx, NiktoAdapter())
    assert ids(findings) == {"NIKTO-999103", "NIKTO-999104"}
    admin = next(f for f in findings if f.rule_id == "NIKTO-999103")
    assert admin.url == "https://fixture.test/admin/" and admin.severity is Severity.MEDIUM


def test_nikto_accepts_host_list_form(ctx):
    findings = nikto.parse([NIKTO_JSON], ctx, NiktoAdapter())
    assert ids(findings) == {"NIKTO-999103", "NIKTO-999104"}


# --------------------------------------------------------------------------- Wapiti

WAPITI_JSON = {
    "vulnerabilities": {
        "SQL Injection": [{"method": "GET", "path": "/item?id=1", "parameter": "id",
                           "info": "SQL injection via id", "http_request": "GET /item?id=1 HTTP/1.1"}],
        "Cross Site Scripting": [{"method": "GET", "path": "/search?q=x", "parameter": "q", "info": "Reflected XSS"}],
        "Backup file": [],  # empty category skipped
    },
    "classifications": {
        "SQL Injection": {"desc": "SQL injection", "sol": "Use prepared statements", "ref": {"CWE-89": "http://x"}},
    },
}


def test_wapiti_maps_categories_to_cwe(ctx):
    findings = wapiti.parse(WAPITI_JSON, ctx, WapitiAdapter())
    assert ids(findings) == {"WAPITI-SQL-INJECTION-0", "WAPITI-CROSS-SITE-SCRIPTING-0"}
    sqli = next(f for f in findings if "SQL" in f.rule_id)
    assert sqli.severity is Severity.HIGH and sqli.cwe == "CWE-89"
    assert sqli.url == "https://fixture.test/item?id=1" and "param: id" in sqli.evidence
    xss = next(f for f in findings if "SCRIPTING" in f.rule_id)
    assert xss.severity is Severity.MEDIUM and xss.cwe == "CWE-79"


# --------------------------------------------------------------------------- sqlmap

SQLMAP_STDOUT = """
[*] starting @ 12:00:00
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1

    Type: error-based
    Title: MySQL >= 5.0 error-based
    Payload: id=1 AND GTID_SUBSET(...)
---
[*] shutting down
"""


def test_sqlmap_parses_confirmed_injection(ctx):
    ctx.url = "https://fixture.test/item?id=1"
    findings = sqlmap.parse(SQLMAP_STDOUT, ctx, SqlmapAdapter())
    assert ids(findings) == {"SQLMAP-GET-ID"}
    f = findings[0]
    assert f.severity is Severity.CRITICAL and f.confidence is Confidence.CERTAIN and f.cwe == "CWE-89"
    assert "boolean-based blind" in f.evidence and "error-based" in f.evidence


def test_sqlmap_no_injection_point_means_no_findings(ctx):
    assert sqlmap.parse("[*] no injection point found", ctx, SqlmapAdapter()) == []


def test_sqlmap_skips_urls_without_parameters(ctx):
    assert SqlmapAdapter().applicable(ctx) == "URL has no parameters to test"
    ctx.url = "https://fixture.test/item?id=1"
    assert SqlmapAdapter().applicable(ctx) is None


# --------------------------------------------------------------------------- active-mode gating

def test_active_tools_require_explicit_opt_in():
    with pytest.raises(ValidationError, match="requires active=true"):
        AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1",
                     scope_domains=["example.com"], active_tools=["nmap"])


def test_active_tools_require_scope_domains():
    with pytest.raises(ValidationError, match="requires scope_domains"):
        AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1",
                     active=True, active_tools=["nmap"])


def test_active_tools_reject_passive_and_unknown_names():
    with pytest.raises(ValidationError, match="non-active"):
        AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1",
                     active=True, scope_domains=["example.com"], active_tools=["zap"])


def test_valid_active_request_normalizes_names():
    req = AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1", active=True,
                       scope_domains=["example.com"], active_tools=["NMAP", "nmap", " sqlmap "])
    assert req.active_tools == ["nmap", "sqlmap"]


def test_auditor_builds_passive_and_active_adapters():
    from app.engine.passive_auditor import PassiveAuditor

    req = AuditRequest(subdomains=["a.example.com"], authorization_ref="ENG-1", active=True,
                       scope_domains=["example.com"], tools=["zap"], active_tools=["nmap", "nikto"])
    names = {a.name for a in PassiveAuditor._build_adapters(req)}
    assert names == {"zap", "nmap", "nikto"}


def test_auditor_omits_active_adapters_when_not_opted_in():
    from app.engine.passive_auditor import PassiveAuditor

    # active=False means active_tools never run even if set programmatically after construction
    req = AuditRequest.model_construct(subdomains=["a.example.com"], authorization_ref="ENG-1",
                                       active=False, scope_domains=[], tools=["zap"], active_tools=["nmap"])
    names = {a.name for a in PassiveAuditor._build_adapters(req)}
    assert names == {"zap"}


def test_registries_are_disjoint():
    assert set(PASSIVE_ADAPTERS) & set(ACTIVE_ADAPTERS) == set()
    assert set(ACTIVE_ADAPTERS) == {"nmap", "nuclei", "nikto", "wapiti", "sqlmap"}
