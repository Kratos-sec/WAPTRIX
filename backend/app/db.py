"""SQLite persistence for audits, per-subdomain results and findings."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.models.audit import AuditListItem, AuditRequest, AuditResult, AuditStatus, RunEvent, Stage, StageStatus

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "waptrix.db"

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS audits (
    id               TEXT PRIMARY KEY,
    authorization_ref TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    completed_at     TEXT,
    overall_score    INTEGER,
    grade            TEXT,
    subdomains_total INTEGER DEFAULT 0,
    total_findings   INTEGER DEFAULT 0,
    demo             INTEGER DEFAULT 0,
    error            TEXT,
    request_json     TEXT,
    result_json      TEXT
);
CREATE TABLE IF NOT EXISTS subdomain_results (
    audit_id   TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    subdomain  TEXT NOT NULL,
    reachable  INTEGER NOT NULL,
    score      INTEGER,
    grade      TEXT,
    finding_count INTEGER DEFAULT 0,
    PRIMARY KEY (audit_id, subdomain)
);
CREATE TABLE IF NOT EXISTS findings (
    audit_id   TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    subdomain  TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    severity   TEXT NOT NULL,
    owasp      TEXT NOT NULL,
    cvss_score REAL,
    correlation_score REAL,
    admitted   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (audit_id, finding_id)
);
CREATE TABLE IF NOT EXISTS run_events (
    audit_id    TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    at          TEXT NOT NULL,
    stage       TEXT NOT NULL,
    status      TEXT NOT NULL,
    subdomain   TEXT,
    round       INTEGER NOT NULL DEFAULT 0,
    detail      TEXT,
    counts_json TEXT,
    duration_ms INTEGER,
    PRIMARY KEY (audit_id, seq)
);
CREATE TABLE IF NOT EXISTS tool_runs (
    audit_id      TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    subdomain     TEXT NOT NULL,
    tool          TEXT NOT NULL,
    stage         TEXT,
    round         INTEGER NOT NULL DEFAULT 0,
    target_url    TEXT,
    started_at    TEXT,
    duration_s    REAL,
    exit_code     INTEGER,
    timed_out     INTEGER NOT NULL DEFAULT 0,
    error         TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_audit ON tool_runs(audit_id, subdomain);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_audits_created ON audits(created_at DESC);
"""


# Columns added after the first schema; databases created earlier get them via ALTER TABLE.
_ADDED_COLUMNS = {
    "findings": [("correlation_score", "REAL"), ("admitted", "INTEGER NOT NULL DEFAULT 1")],
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in _ADDED_COLUMNS.items():
        present = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in present:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _event_row(audit_id: str, e: RunEvent) -> tuple:
    return (audit_id, e.seq, e.at.isoformat(), e.stage.value, e.status.value, e.subdomain, e.round, e.detail,
            json.dumps(e.counts), e.duration_ms)


_EVENT_INSERT = (
    "INSERT OR REPLACE INTO run_events (audit_id, seq, at, stage, status, subdomain, round, detail, counts_json,"
    " duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


class AuditStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or os.environ.get("WAPTRIX_DB", DEFAULT_DB_PATH))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            _migrate(conn)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------ writes

    def create_running(self, audit_id: str, request: AuditRequest) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO audits (id, authorization_ref, status, created_at, subdomains_total, request_json)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    audit_id,
                    request.authorization_ref,
                    AuditStatus.RUNNING.value,
                    now,
                    len(request.subdomains),
                    request.model_dump_json(),
                ),
            )

    def mark_failed(self, audit_id: str, error: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE audits SET status = ?, error = ?, completed_at = ? WHERE id = ?",
                (AuditStatus.FAILED.value, error, datetime.now(timezone.utc).isoformat(), audit_id),
            )

    def save(self, result: AuditResult) -> None:
        payload = result.model_dump_json()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE audit_id = ?", (result.id,))
            conn.execute("DELETE FROM tool_runs WHERE audit_id = ?", (result.id,))
            conn.execute("DELETE FROM subdomain_results WHERE audit_id = ?", (result.id,))
            conn.execute(
                """
                INSERT INTO audits (id, authorization_ref, status, created_at, completed_at, overall_score,
                                    grade, subdomains_total, total_findings, demo, error, request_json, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status, completed_at = excluded.completed_at,
                    overall_score = excluded.overall_score, grade = excluded.grade,
                    subdomains_total = excluded.subdomains_total, total_findings = excluded.total_findings,
                    demo = excluded.demo, error = excluded.error, result_json = excluded.result_json
                """,
                (
                    result.id,
                    result.authorization_ref,
                    result.status.value,
                    result.created_at.isoformat(),
                    result.completed_at.isoformat() if result.completed_at else None,
                    result.summary.overall_score,
                    result.summary.grade,
                    result.summary.subdomains_total,
                    result.summary.total_findings,
                    int(result.demo),
                    result.error,
                    result.request.model_dump_json() if result.request else None,
                    payload,
                ),
            )
            conn.executemany(
                "INSERT INTO subdomain_results (audit_id, subdomain, reachable, score, grade, finding_count)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (result.id, s.subdomain, int(s.reachable), s.score, s.grade, len(s.findings))
                    for s in result.subdomains
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO findings (audit_id, finding_id, subdomain, rule_id, severity, owasp, cvss_score,"
                " correlation_score, admitted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (result.id, f.id, f.subdomain, f.rule_id, f.severity.value, json.dumps(f.owasp), f.cvss_score,
                     f.correlation_score, int(admitted))
                    for s in result.subdomains
                    for admitted, group in ((True, s.findings), (False, s.retest_queue))
                    for f in group
                ],
            )
            conn.executemany(
                "INSERT INTO tool_runs (audit_id, subdomain, tool, stage, round, target_url, started_at, duration_s,"
                " exit_code, timed_out, error, finding_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (result.id, s.subdomain, r.tool, r.stage, r.round, r.target_url,
                     r.started_at.isoformat() if r.started_at else None, r.duration_s, r.exit_code,
                     int(r.timed_out), r.error, r.finding_count)
                    for s in result.subdomains
                    for r in s.tool_runs
                ],
            )
            if result.run_log:  # the final log is authoritative over events streamed while running
                conn.execute("DELETE FROM run_events WHERE audit_id = ?", (result.id,))
                conn.executemany(_EVENT_INSERT, [_event_row(result.id, e) for e in result.run_log])

    def append_event(self, audit_id: str, event: RunEvent) -> None:
        """Persist one run-log event as it happens, so a running audit's log can be followed live."""
        with self._lock, self._connect() as conn:
            conn.execute(_EVENT_INSERT, _event_row(audit_id, event))

    def delete(self, audit_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM audits WHERE id = ?", (audit_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ reads

    def get(self, audit_id: str) -> AuditResult | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
        if row is None:
            return None
        if row["result_json"]:
            return AuditResult.model_validate_json(row["result_json"])
        request = AuditRequest.model_validate_json(row["request_json"]) if row["request_json"] else None
        return AuditResult(
            id=row["id"],
            authorization_ref=row["authorization_ref"],
            status=AuditStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            request=request,
            error=row["error"],
            demo=bool(row["demo"]),
        )

    def list(self, limit: int = 100) -> list[AuditListItem]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, authorization_ref, status, created_at, completed_at, overall_score, grade,"
                " subdomains_total, total_findings, demo FROM audits ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            AuditListItem(
                id=r["id"],
                authorization_ref=r["authorization_ref"],
                status=AuditStatus(r["status"]),
                created_at=datetime.fromisoformat(r["created_at"]),
                completed_at=datetime.fromisoformat(r["completed_at"]) if r["completed_at"] else None,
                overall_score=r["overall_score"],
                grade=r["grade"] or "N/A",
                subdomains_total=r["subdomains_total"] or 0,
                total_findings=r["total_findings"] or 0,
                demo=bool(r["demo"]),
            )
            for r in rows
        ]

    def events(self, audit_id: str, after: int = 0) -> list[RunEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM run_events WHERE audit_id = ? AND seq > ? ORDER BY seq", (audit_id, after)
            ).fetchall()
        return [
            RunEvent(
                seq=r["seq"],
                at=datetime.fromisoformat(r["at"]),
                stage=Stage(r["stage"]),
                status=StageStatus(r["status"]),
                subdomain=r["subdomain"],
                round=r["round"],
                detail=r["detail"] or "",
                counts=json.loads(r["counts_json"] or "{}"),
                duration_ms=r["duration_ms"],
            )
            for r in rows
        ]

    def recover_interrupted(self) -> int:
        """Audits left 'running' by a previous process can never finish; mark them failed."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE audits SET status = ?, error = ? WHERE status = ?",
                (AuditStatus.FAILED.value, "interrupted: server restarted during audit", AuditStatus.RUNNING.value),
            )
            return cur.rowcount
