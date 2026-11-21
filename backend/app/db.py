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

from app.models.audit import AuditListItem, AuditRequest, AuditResult, AuditStatus

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
    PRIMARY KEY (audit_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_audits_created ON audits(created_at DESC);
"""


class AuditStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or os.environ.get("WAPTRIX_DB", DEFAULT_DB_PATH))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)

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
                "INSERT OR IGNORE INTO findings (audit_id, finding_id, subdomain, rule_id, severity, owasp, cvss_score)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (result.id, f.id, f.subdomain, f.rule_id, f.severity.value, json.dumps(f.owasp), f.cvss_score)
                    for s in result.subdomains
                    for f in s.findings
                ],
            )

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

    def recover_interrupted(self) -> int:
        """Audits left 'running' by a previous process can never finish; mark them failed."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE audits SET status = ?, error = ? WHERE status = ?",
                (AuditStatus.FAILED.value, "interrupted: server restarted during audit", AuditStatus.RUNNING.value),
            )
            return cur.rowcount
