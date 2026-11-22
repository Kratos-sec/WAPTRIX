"""Stage scheduler (S1–S6), run log, S3 application map, re-test loop and their persistence."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import httpx
import pytest
from bs4 import BeautifulSoup

from app.db import AuditStore
from app.engine.passive_auditor import PassiveAuditor
from app.engine.stages import MAX_MAP_ENDPOINTS, RunLog, build_app_map, summarize_stages
from app.models.audit import AuditRequest, Endpoint, Stage, StageStatus
from app.models.finding import Confidence, Severity
from app.tools.adapters.base import AdapterResult, ToolAdapter
from tests.conftest import good_tls
from tests.test_passive_checks import StaticTLS

HOST = "shop.example.com"
PAGE = f"""
<html><body>
  <a href="/item?id=1">item</a>
  <a href="/item?id=2#reviews">same endpoint, other value</a>
  <a href="/about">about</a>
  <a href="https://other.example.net/x?y=1">off-host</a>
  <form action="/find" method="get"><input name="term"><input type="submit" name="go"></form>
  <form action="/login" method="post"><input name="user"><input name="pass" type="password"></form>
  <script src="/app.js"></script>
</body></html>
"""


def _transport(page: str = PAGE) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"Location": f"https://{request.url.host}/"})
        if request.url.path == "/":
            return httpx.Response(200, html=page)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


async def _resolver(host):
    return ["93.184.216.34"]


def _auditor(request: AuditRequest, adapters=None, page: str = PAGE, run_log: RunLog | None = None):
    return PassiveAuditor(request, transport=_transport(page), tls_inspector=StaticTLS(good_tls()),
                          resolver=_resolver, adapters=adapters or [], run_log=run_log)


# --------------------------------------------------------------------------- run log


def test_stage_context_records_completion_skip_and_failure():
    seen = []
    log = RunLog(sink=seen.append)
    with log.stage(Stage.S2, "a.example.com") as s:
        s.counts = {"findings": 3}
    with log.stage(Stage.S4, "a.example.com") as s:
        s.skip("passive mode")
    with pytest.raises(RuntimeError), log.stage(Stage.S5, "a.example.com"):
        raise RuntimeError("boom")

    assert [(e.stage, e.status) for e in log.events] == [
        (Stage.S2, StageStatus.STARTED), (Stage.S2, StageStatus.COMPLETED),
        (Stage.S4, StageStatus.STARTED), (Stage.S4, StageStatus.SKIPPED),
        (Stage.S5, StageStatus.STARTED), (Stage.S5, StageStatus.FAILED),
    ]
    assert [e.seq for e in log.events] == list(range(1, 7))
    assert log.events[1].counts == {"findings": 3} and log.events[1].duration_ms is not None
    assert log.events[3].detail == "passive mode"
    assert "boom" in log.events[5].detail
    assert seen == log.events


def test_failing_sink_never_breaks_the_log():
    def sink(event):
        raise OSError("disk full")

    log = RunLog(sink=sink)
    with log.stage(Stage.S1):
        pass
    assert len(log.events) == 2


def test_summarize_stages_aggregates_hosts_and_rounds():
    log = RunLog()
    for host in ("a", "b"):
        with log.stage(Stage.S5, host) as s:
            s.counts = {"admitted": 2}
    with log.stage(Stage.S5, "a", round=1) as s:
        s.counts = {"admitted": 1}
    with log.stage(Stage.S4, "a") as s:
        s.skip("passive mode")

    by_stage = {s.stage: s for s in summarize_stages(log.events)}
    assert [s.stage for s in summarize_stages(log.events)] == [Stage.S4, Stage.S5]
    assert by_stage[Stage.S5].hosts == 2 and by_stage[Stage.S5].runs == 3
    assert by_stage[Stage.S5].counts == {"admitted": 5}
    assert by_stage[Stage.S4].status == StageStatus.SKIPPED and by_stage[Stage.S4].runs == 0


# --------------------------------------------------------------------------- S3 application map


def test_app_map_inventories_same_host_endpoints_and_parameters():
    page_url = f"https://{HOST}/"
    app_map = build_app_map(HOST, page_url, BeautifulSoup(PAGE, "html.parser"))
    by_source = {(e.source, e.method, e.url) for e in app_map.endpoints}

    assert ("page", "GET", page_url) in by_source
    assert ("link", "GET", f"https://{HOST}/item?id=1") in by_source
    assert ("form", "GET", f"https://{HOST}/find?term=1") in by_source  # submit button is not a parameter
    assert ("form", "POST", f"https://{HOST}/login") in by_source
    assert ("script", "GET", f"https://{HOST}/app.js") in by_source
    assert all("other.example.net" not in e.url for e in app_map.endpoints)
    assert sum(1 for e in app_map.endpoints if "/item" in e.url) == 1  # same path + params collapse
    assert app_map.parameters == ["id", "pass", "term", "user"]
    assert [e.url for e in app_map.parameterised()] == [f"https://{HOST}/item?id=1", f"https://{HOST}/find?term=1"]


def test_app_map_merges_extra_endpoints_and_caps_size():
    links = "".join(f'<a href="/p{i}">x</a>' for i in range(MAX_MAP_ENDPOINTS + 20))
    extra = [Endpoint(url=f"https://{HOST}/search?q=x", params=["q"], source="retest")]
    app_map = build_app_map(HOST, f"https://{HOST}/", BeautifulSoup(links, "html.parser"), extra)
    assert len(app_map.endpoints) == MAX_MAP_ENDPOINTS and app_map.truncated

    small = build_app_map(HOST, f"https://{HOST}/", None, extra)
    assert [e.source for e in small.endpoints] == ["page", "retest"]


# --------------------------------------------------------------------------- scheduler


async def test_passive_run_walks_all_stages_and_skips_s4():
    request = AuditRequest(subdomains=[HOST, "bad host"], authorization_ref="ENG-STAGES-1", requests_per_second=10)
    audit = await _auditor(request).run()

    host_stages = [(e.stage, e.status) for e in audit.run_log
                   if e.subdomain == HOST and e.status not in (StageStatus.STARTED, StageStatus.INFO)]
    assert host_stages == [
        (Stage.S2, StageStatus.COMPLETED), (Stage.S3, StageStatus.COMPLETED), (Stage.S4, StageStatus.SKIPPED),
        (Stage.S5, StageStatus.COMPLETED), (Stage.S6, StageStatus.COMPLETED),
    ]
    first, last = audit.run_log[0], audit.run_log[-1]
    assert (first.stage, first.subdomain) == (Stage.S1, None)
    s1_done = next(e for e in audit.run_log if e.stage == Stage.S1 and e.status == StageStatus.COMPLETED)
    assert s1_done.counts == {"targets": 1, "rejected": 1} and "passive mode" in s1_done.detail
    assert "ENG-STAGES-1" in s1_done.detail and "10 req/s" in s1_done.detail
    assert (last.stage, last.subdomain, last.status) == (Stage.S6, None, StageStatus.COMPLETED)
    assert [s.stage for s in audit.stages] == list(Stage)

    sub = audit.subdomains[0]
    assert sub.app_map is not None and len(sub.app_map.parameterised()) == 2
    assert sub.retest_rounds_run == 0 and sub.score is not None


async def test_unreachable_host_goes_from_s2_straight_to_s6():
    async def resolver(host):
        return ["10.0.0.7"]

    request = AuditRequest(subdomains=["intranet.example.com"], authorization_ref="ENG-STAGES-2", requests_per_second=10)
    audit = await PassiveAuditor(request, transport=_transport(), tls_inspector=StaticTLS(good_tls()),
                                 resolver=resolver, adapters=[]).run()
    stages = [e.stage for e in audit.run_log if e.subdomain and e.status != StageStatus.STARTED]
    assert stages == [Stage.S2, Stage.S6]
    assert "scope guard" in next(e.detail for e in audit.run_log if e.stage == Stage.S2 and e.subdomain
                                 and e.status == StageStatus.COMPLETED)


class FakeWapiti(ToolAdapter):
    """Scanner that spidered an endpoint outside the S3 map and is only tentative about it."""

    name = "wapiti"

    def __init__(self):
        self.urls: list[str] = []

    async def execute(self, ctx, workdir):
        self.urls.append(ctx.url)
        url = f"https://{HOST}/search?q=x"
        return AdapterResult(tool=self.name, findings=[self.unmapped(
            ctx, "sql-q", "SQL Injection", Severity.HIGH, Confidence.TENTATIVE, 89, "maybe", "q=x'", url=url)])


class FakeSqlmap(ToolAdapter):
    """Confirmation engine: confirms injection only where it really exists (/search)."""

    name = "sqlmap"
    per_endpoint = True

    def __init__(self):
        self.urls: list[str] = []

    async def execute(self, ctx, workdir):
        self.urls.append(ctx.url)
        findings = []
        if "/search" in ctx.url:
            findings.append(self.unmapped(ctx, "GET-q", "SQL injection confirmed", Severity.CRITICAL,
                                          Confidence.CERTAIN, 89, "confirmed", "q injectable"))
        return AdapterResult(tool=self.name, findings=findings)


def _sqli(findings):
    return [f for f in findings if f.cwe == "CWE-89"]


def _active_request(**overrides) -> AuditRequest:
    return AuditRequest(subdomains=[HOST], authorization_ref="ENG-STAGES-3", requests_per_second=10, active=True,
                        scope_domains=["example.com"], **overrides)


async def test_s4_runs_per_endpoint_engines_on_map_and_retest_loop_confirms():
    wapiti, sqlmap = FakeWapiti(), FakeSqlmap()
    audit = await _auditor(_active_request(), adapters=[wapiti, sqlmap]).run()
    sub = audit.subdomains[0]

    # S4: sqlmap aimed at each parameterised GET endpoint of the map; wapiti once from the page.
    assert sqlmap.urls[:2] == [f"https://{HOST}/item?id=1", f"https://{HOST}/find?term=1"]
    assert wapiti.urls[0] == f"https://{HOST}/"

    # S5 queued wapiti's tentative candidate; the re-test round re-entered S3 with its exact endpoint
    # and the confirmation engine reproduced it, lifting it over τ.
    assert sub.retest_rounds_run == 1
    assert f"https://{HOST}/search?q=x" in sqlmap.urls and f"https://{HOST}/search?q=x" in wapiti.urls
    assert any(e.source == "retest" and e.url.endswith("/search?q=x") for e in sub.app_map.endpoints)
    sqli = [f for f in sub.findings if f.cwe == "CWE-89"]
    assert len(sqli) == 1 and sqli[0].correlation.confirmed and set(sqli[0].sources) == {"sqlmap", "wapiti"}
    assert _sqli(sub.retest_queue) == []

    rounds = {(e.stage, e.round) for e in audit.run_log if e.status == StageStatus.COMPLETED and e.subdomain}
    assert {(Stage.S3, 1), (Stage.S4, 1), (Stage.S5, 1)} <= rounds
    retest_runs = [r for r in sub.tool_runs if r.round == 1]
    assert {r.tool for r in retest_runs} == {"sqlmap", "wapiti"} and all(r.stage == "S4" for r in retest_runs)
    s5_first = next(e for e in audit.run_log if e.stage == Stage.S5 and e.round == 0 and e.status == StageStatus.COMPLETED)
    assert s5_first.counts["queued"] == 2  # wapiti candidate + tentative built-in CSRF on the login form


async def test_max_endpoints_caps_per_endpoint_engine_and_zero_rounds_disables_loop():
    sqlmap = FakeSqlmap()
    audit = await _auditor(_active_request(max_endpoints=1, retest_rounds=0), adapters=[FakeWapiti(), sqlmap]).run()
    sub = audit.subdomains[0]
    assert sqlmap.urls == [f"https://{HOST}/item?id=1"]
    assert sub.retest_rounds_run == 0 and len(_sqli(sub.retest_queue)) == 1


async def test_retest_loop_closes_when_no_untried_hypothesis_remains():
    class SilentSqlmap(FakeSqlmap):
        async def execute(self, ctx, workdir):
            self.urls.append(ctx.url)
            return AdapterResult(tool=self.name)

    sqlmap = SilentSqlmap()
    audit = await _auditor(_active_request(retest_rounds=3), adapters=[FakeWapiti(), sqlmap]).run()
    sub = audit.subdomains[0]
    # Round 1 tries /search with both engines; nothing new to try after that, so the loop stops early.
    assert sub.retest_rounds_run == 1 and len(_sqli(sub.retest_queue)) == 1
    assert sqlmap.urls.count(f"https://{HOST}/search?q=x") == 1
    closed = [e for e in audit.run_log if e.status == StageStatus.INFO]
    assert len(closed) == 1 and closed[0].round == 2 and "re-test loop closed" in closed[0].detail


async def test_retest_findings_are_voted_from_raw_not_previous_merge():
    # Re-correlation must not double-count: two rounds produce one finding with each engine once.
    audit = await _auditor(_active_request(), adapters=[FakeWapiti(), FakeSqlmap()]).run()
    sqli = [f for f in audit.subdomains[0].findings if f.cwe == "CWE-89"]
    assert len(sqli) == 1 and sorted(sqli[0].sources) == ["sqlmap", "wapiti"]
    assert sqli[0].correlation.detectors == ["sqlmap", "wapiti"]


# --------------------------------------------------------------------------- persistence


async def test_store_persists_run_log_tool_runs_and_queue(tmp_path):
    store = AuditStore(tmp_path / "w.db")
    audit = await _auditor(_active_request(retest_rounds=0), adapters=[FakeWapiti(), FakeSqlmap()]).run()
    store.create_running(audit.id, audit.request)
    store.append_event(audit.id, audit.run_log[0])
    assert [e.seq for e in store.events(audit.id)] == [1]

    store.save(audit)
    events = store.events(audit.id)
    assert [e.seq for e in events] == [e.seq for e in audit.run_log]
    assert events[-1].stage == Stage.S6 and store.events(audit.id, after=len(events) - 1) == events[-1:]
    assert store.get(audit.id).stages == audit.stages

    with sqlite3.connect(tmp_path / "w.db") as conn:
        runs = conn.execute("SELECT tool, stage, target_url FROM tool_runs WHERE audit_id = ?", (audit.id,)).fetchall()
        queued = conn.execute("SELECT rule_id, correlation_score FROM findings WHERE audit_id = ? AND admitted = 0",
                              (audit.id,)).fetchall()
    assert ("sqlmap", "S4", f"https://{HOST}/item?id=1") in runs
    wapiti_queued = [q for q in queued if q[0].startswith("WAPITI-")]
    assert len(wapiti_queued) == 1 and wapiti_queued[0][1] < 0.55

    assert store.delete(audit.id)
    assert store.events(audit.id) == []


def test_store_migrates_findings_table_from_older_schema(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE findings (audit_id TEXT NOT NULL, finding_id TEXT NOT NULL, subdomain TEXT NOT NULL,"
                     " rule_id TEXT NOT NULL, severity TEXT NOT NULL, owasp TEXT NOT NULL, cvss_score REAL,"
                     " PRIMARY KEY (audit_id, finding_id))")
    AuditStore(path)
    with sqlite3.connect(path) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    assert {"correlation_score", "admitted"} <= cols


def test_log_endpoint(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("WAPTRIX_DB", str(tmp_path / "api.db"))
    from app.main import app

    with TestClient(app) as client:
        demo = client.post("/api/demo").json()
        assert client.get(f"/api/audits/{demo['id']}/log").json() == []
        assert client.get("/api/audits/nope/log").status_code == 404
        store = app.state.store
        log = RunLog(sink=lambda e: store.append_event(demo["id"], e))
        with log.stage(Stage.S2, "www.acme-corp.example"):
            pass
        body = client.get(f"/api/audits/{demo['id']}/log", params={"after": 1}).json()
        assert [(e["seq"], e["stage"], e["status"]) for e in body] == [(2, "S2", "completed")]
        assert datetime.fromisoformat(body[0]["at"]).tzinfo == timezone.utc
