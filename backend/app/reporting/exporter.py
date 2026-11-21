"""Export a full audit or a single subdomain to JSON, CSV, SARIF 2.1.0, HTML and PDF."""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.compliance import categories, load_mapping
from app.models.audit import ENGINE_VERSION, AuditResult
from app.models.finding import SEVERITY_RANK, PassiveFinding, Severity

logger = logging.getLogger("waptrix.reporting")

TEMPLATE_DIR = Path(__file__).with_name("templates")
FORMATS = ("json", "csv", "sarif", "html", "pdf")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Kratos-sec/WAPTRIX"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SARIF_PRECISION = {"certain": "very-high", "firm": "high", "tentative": "medium"}

CSV_COLUMNS = [
    "subdomain",
    "severity",
    "confidence",
    "rule_id",
    "title",
    "url",
    "owasp_2025",
    "cwe",
    "wstg",
    "cvss_score",
    "cvss_vector",
    "sources",
    "evidence",
    "remediation",
    "finding_id",
]


@dataclass
class ExportArtifact:
    content: bytes
    media_type: str
    extension: str
    fallback_note: str | None = None


class ExportError(ValueError):
    pass


def _all_findings(audit: AuditResult) -> list[PassiveFinding]:
    findings = [f for s in audit.subdomains for f in s.findings]
    return sorted(findings, key=lambda f: (-f.severity.rank, f.subdomain, f.rule_id))


def _safe_csv(value: str) -> str:
    """Neutralise spreadsheet formula injection from attacker-controlled evidence."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


# --------------------------------------------------------------------------- JSON / CSV


def export_json(audit: AuditResult) -> bytes:
    return audit.model_dump_json(indent=2).encode("utf-8")


def export_csv(audit: AuditResult) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for f in _all_findings(audit):
        writer.writerow(
            {
                "subdomain": f.subdomain,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "rule_id": f.rule_id,
                "title": _safe_csv(f.title),
                "url": _safe_csv(f.url),
                "owasp_2025": ";".join(f.owasp),
                "cwe": f.cwe,
                "wstg": f.wstg or "",
                "cvss_score": f"{f.cvss_score:.1f}" if f.cvss_score is not None else "",
                "cvss_vector": f.cvss_vector or "",
                "sources": ";".join(f.sources),
                "evidence": _safe_csv(f.evidence),
                "remediation": _safe_csv(f.remediation),
                "finding_id": f.id,
            }
        )
    return buffer.getvalue().encode("utf-8-sig")


# --------------------------------------------------------------------------- SARIF 2.1.0


def _rule_name(title: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", title)
    return "".join(w[:1].upper() + w[1:] for w in words)


def _meta_from_finding(f) -> dict:
    """Rule metadata for tool-specific rules that have no entry in owasp_2025_map.json."""
    return {
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        "references": f.references,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "wstg": f.wstg,
        "cvss_vector": f.cvss_vector,
    }


def build_sarif(audit: AuditResult) -> dict:
    mapping = load_mapping()["rules"]
    findings = _all_findings(audit)
    used_rules = sorted({f.rule_id for f in findings})
    rule_index = {rule_id: i for i, rule_id in enumerate(used_rules)}

    rules = []
    for rule_id in used_rules:
        sample = next(f for f in findings if f.rule_id == rule_id)
        meta = mapping.get(rule_id) or _meta_from_finding(sample)
        refs = meta.get("references", [])
        rules.append(
            {
                "id": rule_id,
                "name": _rule_name(meta["title"]),
                "shortDescription": {"text": meta["title"]},
                "fullDescription": {"text": meta["description"]},
                "help": {"text": meta["remediation"], "markdown": f"**Remediation:** {meta['remediation']}"},
                **({"helpUri": refs[0]} if refs else {}),
                "defaultConfiguration": {"level": _SARIF_LEVEL[Severity(meta["severity"])]},
                "properties": {
                    "tags": ["security", *([meta["cwe"]] if meta["cwe"] else []), *meta["owasp"], *([meta["wstg"]] if meta.get("wstg") else [])],
                    "precision": _SARIF_PRECISION[meta["confidence"]],
                    **({"security-severity": f"{sample.cvss_score:.1f}", "cvssV31Vector": meta["cvss_vector"]}
                       if sample.cvss_score is not None else {}),
                    "problem.severity": meta["severity"],
                },
            }
        )

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title} on {f.subdomain}. Evidence: {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": f.url}},
                        "logicalLocations": [{"name": f.subdomain, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {"waptrixFindingId/v1": f.id},
                "properties": {
                    "subdomain": f.subdomain,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "owasp2025": f.owasp,
                    "cwe": f.cwe,
                    "wstg": f.wstg,
                    "cvssScore": f.cvss_score,
                    "cvssVector": f.cvss_vector,
                    "sources": f.sources,
                    "toolRefs": f.tool_refs,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WAPTrix",
                        "fullName": "WAPTrix Passive Web Application Auditor",
                        "version": ENGINE_VERSION,
                        "semanticVersion": ENGINE_VERSION,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"waptrix/{audit.authorization_ref}/{audit.id}"},
                "invocations": [
                    {
                        "executionSuccessful": audit.status.value == "completed",
                        "startTimeUtc": audit.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                        **(
                            {"endTimeUtc": audit.completed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
                            if audit.completed_at
                            else {}
                        ),
                        "properties": {
                            "authorizationRef": audit.authorization_ref,
                            "mode": "passive",
                            "targets": [s.subdomain for s in audit.subdomains],
                        },
                    }
                ],
                "properties": {
                    "overallScore": audit.summary.overall_score,
                    "grade": audit.summary.grade,
                },
                "results": results,
            }
        ],
    }


def export_sarif(audit: AuditResult) -> bytes:
    return json.dumps(build_sarif(audit), indent=2).encode("utf-8")


# --------------------------------------------------------------------------- HTML / PDF

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _fmt_dt(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


_env.filters["dt"] = _fmt_dt


def export_html(audit: AuditResult, for_pdf: bool = False) -> bytes:
    template = _env.get_template("report.html")
    severities = [s.value for s in sorted(Severity, key=lambda s: -SEVERITY_RANK[s])]
    html = template.render(
        audit=audit,
        summary=audit.summary,
        categories=categories(),
        severities=severities,
        findings=_all_findings(audit),
        generated_at=datetime.now(timezone.utc),
        engine_version=ENGINE_VERSION,
        for_pdf=for_pdf,
        single=len(audit.subdomains) == 1,
    )
    return html.encode("utf-8")


def export_pdf(audit: AuditResult) -> ExportArtifact:
    """Render PDF via WeasyPrint; fall back to print-ready HTML when native libraries are unavailable."""
    html = export_html(audit, for_pdf=True)
    try:
        from weasyprint import HTML  # imported lazily: requires Pango/Cairo system libraries
    except (ImportError, OSError) as exc:
        logger.warning("WeasyPrint unavailable (%s); returning HTML fallback", exc)
        return ExportArtifact(
            content=html,
            media_type="text/html; charset=utf-8",
            extension="html",
            fallback_note=f"PDF engine unavailable ({exc.__class__.__name__}); print-ready HTML returned instead",
        )
    pdf = HTML(string=html.decode("utf-8"), base_url=str(TEMPLATE_DIR)).write_pdf()
    return ExportArtifact(content=pdf, media_type="application/pdf", extension="pdf")


# --------------------------------------------------------------------------- dispatch


def render(audit: AuditResult, fmt: str, subdomain: str | None = None) -> ExportArtifact:
    fmt = fmt.lower().strip()
    if fmt not in FORMATS:
        raise ExportError(f"unsupported format {fmt!r}; choose one of {', '.join(FORMATS)}")
    if subdomain:
        try:
            audit = audit.for_subdomain(subdomain)
        except KeyError as exc:
            raise ExportError(f"subdomain {subdomain!r} is not part of audit {audit.id}") from exc
    if fmt == "json":
        return ExportArtifact(export_json(audit), "application/json", "json")
    if fmt == "csv":
        return ExportArtifact(export_csv(audit), "text/csv; charset=utf-8", "csv")
    if fmt == "sarif":
        return ExportArtifact(export_sarif(audit), "application/sarif+json", "sarif")
    if fmt == "html":
        return ExportArtifact(export_html(audit), "text/html; charset=utf-8", "html")
    return export_pdf(audit)


def report_basename(audit: AuditResult, subdomain: str | None = None) -> str:
    ref = re.sub(r"[^A-Za-z0-9._-]+", "_", audit.authorization_ref).strip("_") or "audit"
    stamp = audit.created_at.strftime("%Y%m%d")
    scope = re.sub(r"[^A-Za-z0-9._-]+", "_", subdomain) if subdomain else "full"
    return f"waptrix_{ref}_{stamp}_{scope}"


def write_reports(
    audit: AuditResult,
    out_dir: str | Path,
    formats: list[str] | tuple[str, ...] = FORMATS,
    subdomain: str | None = None,
) -> list[tuple[Path, str | None]]:
    """Write the requested formats to disk. Returns (path, fallback_note) tuples."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = report_basename(audit, subdomain)
    written: list[tuple[Path, str | None]] = []
    for fmt in formats:
        artifact = render(audit, fmt, subdomain=subdomain)
        suffix = artifact.extension if fmt != "pdf" or artifact.extension == "pdf" else "print.html"
        path = out / f"{base}.{suffix}"
        path.write_bytes(artifact.content)
        written.append((path, artifact.fallback_note))
    return written
