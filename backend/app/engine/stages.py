"""Stage scheduler support: run log, per-stage summaries and the Stage S3 application map.

The auditor drives every host through the six stages of the paper's workflow (Section III-C, Fig. 3):

  S1  scope & authorisation   engagement-wide: authorisation record, in-scope host list, request budget
  S2  passive reconnaissance  DNS, read-only GETs, TLS, built-in checks, passive tools
  S3  application map         URL tree and parameter inventory from the content S2 observed (no requests)
  S4  phase controllers       active engines against the map, concurrently under the rate governor
  S5  correlation             cross-tool voting (eq. 1); below-τ candidates re-enter S3 (bounded loop)
  S6  risk & report           per-host scoring, then the engagement summary

Every transition is recorded as a :class:`RunEvent`. A sink (the SQLite store in the API) receives events
as they happen, so a running audit's log can be followed live.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from app.models.audit import (
    STAGE_TITLES,
    ApplicationMap,
    Endpoint,
    RunEvent,
    Stage,
    StageStatus,
    StageSummary,
)

logger = logging.getLogger("waptrix.stages")

EventSink = Callable[[RunEvent], None]
MAX_MAP_ENDPOINTS = 200


class RunLog:
    """Ordered, append-only log of stage events for one audit."""

    def __init__(self, sink: EventSink | None = None) -> None:
        self.events: list[RunEvent] = []
        self.sink = sink

    def emit(self, stage: Stage, status: StageStatus, subdomain: str | None = None, *, round: int = 0,
             detail: str = "", counts: dict[str, int] | None = None, duration_ms: int | None = None) -> RunEvent:
        event = RunEvent(seq=len(self.events) + 1, at=datetime.now(timezone.utc), stage=stage, status=status,
                         subdomain=subdomain, round=round, detail=detail, counts=counts or {},
                         duration_ms=duration_ms)
        self.events.append(event)
        if self.sink is not None:
            try:
                self.sink(event)
            except Exception:  # a failing log sink must never abort the audit
                logger.exception("run log sink failed for %s %s", stage.value, status.value)
        return event

    @contextmanager
    def stage(self, stage: Stage, subdomain: str | None = None, *, round: int = 0,
              detail: str = "") -> Iterator["StageOutcome"]:
        """Emit ``started`` now and ``completed``/``skipped``/``failed`` with duration on exit."""
        self.emit(stage, StageStatus.STARTED, subdomain, round=round, detail=detail)
        outcome = StageOutcome()
        started = time.monotonic()
        try:
            yield outcome
        except BaseException as exc:
            self.emit(stage, StageStatus.FAILED, subdomain, round=round, detail=f"{type(exc).__name__}: {exc}",
                      counts=outcome.counts, duration_ms=_elapsed(started))
            raise
        status = StageStatus.SKIPPED if outcome.skipped else StageStatus.COMPLETED
        self.emit(stage, status, subdomain, round=round, detail=outcome.detail, counts=outcome.counts,
                  duration_ms=_elapsed(started))


class StageOutcome:
    """Filled in by the stage body: what it produced, or why it was skipped."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.detail = ""
        self.skipped = False

    def skip(self, reason: str) -> None:
        self.skipped, self.detail = True, reason


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def summarize_stages(events: list[RunEvent]) -> list[StageSummary]:
    """Collapse the run log into one row per stage, in workflow order."""
    summaries: list[StageSummary] = []
    for stage in Stage:
        finished = [e for e in events if e.stage == stage and e.status != StageStatus.STARTED
                    and e.status != StageStatus.INFO]
        if not finished:
            continue
        statuses = {e.status for e in finished}
        if StageStatus.FAILED in statuses:
            status = StageStatus.FAILED
        elif statuses == {StageStatus.SKIPPED}:
            status = StageStatus.SKIPPED
        else:
            status = StageStatus.COMPLETED
        counts: dict[str, int] = {}
        for e in finished:
            for key, value in e.counts.items():
                counts[key] = counts.get(key, 0) + value
        summaries.append(StageSummary(
            stage=stage,
            name=STAGE_TITLES[stage],
            status=status,
            hosts=len({e.subdomain for e in finished if e.subdomain}),
            runs=sum(1 for e in finished if e.status == StageStatus.COMPLETED),
            duration_ms=sum(e.duration_ms or 0 for e in finished),
            counts=counts,
        ))
    return summaries


# --------------------------------------------------------------------------- Stage S3


def _same_host(url: str, host: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and (parts.hostname or "").lower() == host


def _strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _params(url: str) -> list[str]:
    return sorted({key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


class _MapBuilder:
    def __init__(self, host: str) -> None:
        self.host = host
        self.map = ApplicationMap()
        self._seen: set[tuple[str, str, tuple[str, ...]]] = set()

    def add(self, url: str, method: str, params: list[str], source: str) -> None:
        if not _same_host(url, self.host):
            return
        url = _strip_fragment(url)
        parts = urlsplit(url)
        key = (method, f"{parts.scheme}://{parts.netloc}{parts.path}", tuple(params))
        if key in self._seen:
            return
        if len(self.map.endpoints) >= MAX_MAP_ENDPOINTS:
            self.map.truncated = True
            return
        self._seen.add(key)
        self.map.endpoints.append(Endpoint(url=url, method=method, params=params, source=source))


def build_app_map(host: str, page_url: str, soup: BeautifulSoup | None,
                  extra: list[Endpoint] | None = None) -> ApplicationMap:
    """URL tree and parameter inventory of one host from the page S2 already fetched.

    Purely derived from observed content — S3 sends no requests of its own here; active crawling belongs
    to the S4 engines that spider (ZAP active scan, Wapiti). Only same-host endpoints are kept, so the map
    can never widen the engagement beyond the scope guard's decision.
    """
    builder = _MapBuilder(host.lower())
    builder.add(page_url, "GET", _params(page_url), "page")
    if soup is not None:
        for tag in soup.find_all("a", href=True):
            url = urljoin(page_url, str(tag["href"]).strip())
            builder.add(url, "GET", _params(url), "link")
        for form in soup.find_all("form"):
            action = urljoin(page_url, str(form.get("action") or "").strip() or page_url)
            method = str(form.get("method") or "GET").strip().upper()
            method = method if method in ("GET", "POST") else "GET"
            fields: dict[str, str] = {}
            for field in form.find_all(("input", "select", "textarea")):
                name = str(field.get("name") or "").strip()
                if not name or str(field.get("type") or "").lower() in ("submit", "button", "image", "reset"):
                    continue
                fields.setdefault(name, str(field.get("value") or "1"))
            if method == "GET" and fields:
                parts = urlsplit(action)
                query = urlencode([*parse_qsl(parts.query, keep_blank_values=True), *fields.items()])
                action = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
                builder.add(action, "GET", _params(action), "form")
            else:
                builder.add(action, method, sorted(fields), "form")
        for tag in soup.find_all("script", src=True):
            url = urljoin(page_url, str(tag["src"]).strip())
            builder.add(url, "GET", _params(url), "script")
    for endpoint in extra or []:
        builder.add(endpoint.url, endpoint.method, endpoint.params, endpoint.source)
    return builder.map


__all__ = ["RunLog", "StageOutcome", "EventSink", "summarize_stages", "build_app_map", "MAX_MAP_ENDPOINTS"]
