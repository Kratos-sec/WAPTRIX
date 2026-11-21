"""FastAPI application: REST API for passive audits, compliance data and report exports."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.compliance import categories, load_mapping
from app.compliance.scorer import cvss31_base_score
from app.db import AuditStore
from app.engine.passive_auditor import PassiveAuditor
from app.engine.scope_guard import ScopeError, build_scope
from app.models.audit import ENGINE_VERSION, AuditListItem, AuditRequest, AuditResult, SubdomainResult
from app.reporting.exporter import FORMATS, ExportError, render, report_basename

logger = logging.getLogger("waptrix.api")
logging.basicConfig(level=os.environ.get("WAPTRIX_LOG_LEVEL", "INFO"))

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


class AuditRunner:
    """Tracks background audit tasks and their progress."""

    def __init__(self, store: AuditStore) -> None:
        self.store = store
        self.progress: dict[str, dict[str, Any]] = {}
        self._tasks: set[asyncio.Task] = set()

    def start(self, request: AuditRequest, total: int) -> str:
        audit_id = uuid.uuid4().hex
        self.store.create_running(audit_id, request)
        self.progress[audit_id] = {"done": 0, "total": total, "current": None}
        task = asyncio.create_task(self._run(audit_id, request))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return audit_id

    async def _run(self, audit_id: str, request: AuditRequest) -> None:
        def on_progress(done: int, total: int, current: str) -> None:
            self.progress[audit_id] = {"done": done, "total": total, "current": current}

        try:
            result = await PassiveAuditor(request, progress=on_progress).run(audit_id=audit_id)
            self.store.save(result)
        except Exception as exc:  # surface failure to the client instead of leaving it 'running'
            logger.exception("audit %s failed", audit_id)
            self.store.mark_failed(audit_id, str(exc))
        finally:
            self.progress.pop(audit_id, None)

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = AuditStore()
    recovered = store.recover_interrupted()
    if recovered:
        logger.warning("marked %d interrupted audit(s) as failed", recovered)
    app.state.store = store
    app.state.runner = AuditRunner(store)
    yield
    await app.state.runner.shutdown()


app = FastAPI(
    title="WAPTrix API",
    version=ENGINE_VERSION,
    description="Strictly passive web application security auditing and OWASP Top 10 (2025) compliance.",
    lifespan=lifespan,
)

_origins = [o.strip() for o in os.environ.get(
    "WAPTRIX_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
    expose_headers=["Content-Disposition", "X-WAPTrix-Fallback"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


def _store(request: Request) -> AuditStore:
    return request.app.state.store


def _runner(request: Request) -> AuditRunner:
    return request.app.state.runner


def _get_audit(request: Request, audit_id: str) -> AuditResult:
    audit = _store(request).get(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return audit


@lru_cache(maxsize=1)
def pdf_engine_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


# --------------------------------------------------------------------------- metadata


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": ENGINE_VERSION, "mode": "passive", "pdf_engine": pdf_engine_available()}


@app.get("/api/owasp")
def owasp_categories() -> list[dict[str, Any]]:
    return [{"id": cid, **meta} for cid, meta in categories().items()]


@app.get("/api/rules")
def rules() -> list[dict[str, Any]]:
    return [
        {"id": rid, **meta, "cvss_score": cvss31_base_score(meta["cvss_vector"])}
        for rid, meta in load_mapping()["rules"].items()
    ]


# --------------------------------------------------------------------------- audits


@app.get("/api/audits", response_model=list[AuditListItem])
def list_audits(request: Request, limit: int = Query(100, ge=1, le=500)) -> list[AuditListItem]:
    return _store(request).list(limit=limit)


@app.post("/api/audits", status_code=202)
async def create_audit(request: Request, body: AuditRequest) -> dict[str, Any]:
    try:
        decision = build_scope(
            body.subdomains, body.authorization_ref, scope_domains=body.scope_domains, allow_private=body.allow_private
        )
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit_id = _runner(request).start(body, total=len(decision.targets))
    return {
        "id": audit_id,
        "status": "running",
        "targets": [t.display for t in decision.targets],
        "scope_rejections": [r.model_dump() for r in decision.rejections],
    }


@app.get("/api/audits/{audit_id}")
def get_audit(request: Request, audit_id: str) -> JSONResponse:
    audit = _get_audit(request, audit_id)
    payload = audit.model_dump(mode="json")
    payload["progress"] = _runner(request).progress.get(audit_id)
    return JSONResponse(payload)


@app.get("/api/audits/{audit_id}/subdomains/{subdomain}", response_model=SubdomainResult)
def get_subdomain(request: Request, audit_id: str, subdomain: str) -> SubdomainResult:
    audit = _get_audit(request, audit_id)
    for item in audit.subdomains:
        if item.subdomain == subdomain.lower():
            return item
    raise HTTPException(status_code=404, detail="subdomain not part of this audit")


@app.delete("/api/audits/{audit_id}", status_code=204)
def delete_audit(request: Request, audit_id: str) -> Response:
    if audit_id in _runner(request).progress:
        raise HTTPException(status_code=409, detail="audit still running")
    if not _store(request).delete(audit_id):
        raise HTTPException(status_code=404, detail="audit not found")
    return Response(status_code=204)


@app.post("/api/demo")
async def load_demo(request: Request) -> JSONResponse:
    from sample_data import aload_demo_audit

    audit = await aload_demo_audit()
    _store(request).save(audit)
    return JSONResponse(audit.model_dump(mode="json"))


@app.get("/api/audits/{audit_id}/export")
def export_audit(
    request: Request,
    audit_id: str,
    format: str = Query("json", description=f"One of: {', '.join(FORMATS)}"),
    subdomain: str | None = Query(None, description="Restrict the report to a single subdomain"),
) -> Response:
    audit = _get_audit(request, audit_id)
    if audit.status.value != "completed":
        raise HTTPException(status_code=409, detail=f"audit is {audit.status.value}; exports need a completed audit")
    try:
        artifact = render(audit, format, subdomain=subdomain)
    except ExportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    filename = f"{report_basename(audit, subdomain)}.{artifact.extension}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if artifact.fallback_note:
        headers["X-WAPTrix-Fallback"] = artifact.fallback_note
    return Response(content=artifact.content, media_type=artifact.media_type, headers=headers)


# Serve a production frontend build from the same origin when present.
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
