"""Catalogue of external tools WAPTrix can drive, and runtime detection of which are installed."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from enum import Enum
from importlib import metadata

import httpx
from pydantic import BaseModel

from app.tools.runner import run_tool

_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)*(?:[-#][\w.]+)?)")
DETECT_TIMEOUT = 15.0


class ToolMode(str, Enum):
    PASSIVE = "passive"  # only requests a normal visitor would make
    ACTIVE = "active"  # sends probes or payloads; needs explicit opt-in


class ToolSpec(BaseModel):
    name: str
    display: str
    stage: str  # paper stage: S2 recon, S3 enumeration, S4 testing, S5 confirmation
    modes: list[ToolMode]
    purpose: str
    license: str
    homepage: str
    binaries: list[str] = []  # candidate executable names, first found wins
    version_args: list[str] = ["--version"]
    python_dist: str | None = None  # read version from installed package metadata instead
    http_service: bool = False  # reached over HTTP (ZAP daemon), not a local binary


class ToolStatus(BaseModel):
    name: str
    display: str
    stage: str
    modes: list[ToolMode]
    purpose: str
    license: str
    homepage: str
    available: bool
    version: str | None = None
    location: str | None = None
    detail: str | None = None


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="whatweb", display="WhatWeb", stage="S2", modes=[ToolMode.PASSIVE],
        purpose="Technology fingerprinting from one page load (aggression level 1)",
        license="GPL-2.0", homepage="https://github.com/urbanadventurer/WhatWeb",
        binaries=["whatweb"],
    ),
    ToolSpec(
        name="sslyze", display="SSLyze", stage="S2", modes=[ToolMode.PASSIVE],
        purpose="TLS configuration: protocol and cipher enumeration, certificate chain, OCSP",
        license="AGPL-3.0", homepage="https://github.com/nabla-c0d3/sslyze",
        binaries=["sslyze"], python_dist="sslyze",
    ),
    ToolSpec(
        name="testssl", display="testssl.sh", stage="S2", modes=[ToolMode.PASSIVE],
        purpose="TLS configuration cross-check (vulnerability probes disabled in passive mode)",
        license="GPL-2.0", homepage="https://testssl.sh",
        binaries=["testssl", "testssl.sh"],
    ),
    ToolSpec(
        name="retire", display="Retire.js", stage="S2", modes=[ToolMode.PASSIVE],
        purpose="Known-vulnerable JavaScript libraries, matched on file contents",
        license="Apache-2.0", homepage="https://retirejs.github.io/retire.js/",
        binaries=["retire"],
    ),
    ToolSpec(
        name="zap", display="OWASP ZAP", stage="S2/S3/S4", modes=[ToolMode.PASSIVE, ToolMode.ACTIVE],
        purpose="Spider and passive rules (passive); active scan rules (active)",
        license="Apache-2.0", homepage="https://www.zaproxy.org",
        http_service=True,
    ),
    ToolSpec(
        name="nmap", display="Nmap", stage="S3", modes=[ToolMode.ACTIVE],
        purpose="Open ports and service versions (TCP connect scan)",
        license="NPSL", homepage="https://nmap.org",
        binaries=["nmap"],
    ),
    ToolSpec(
        name="nuclei", display="Nuclei", stage="S4", modes=[ToolMode.ACTIVE],
        purpose="Template-based checks for known misconfigurations and CVEs",
        license="MIT", homepage="https://github.com/projectdiscovery/nuclei",
        binaries=["nuclei"], version_args=["-version"],
    ),
    ToolSpec(
        name="nikto", display="Nikto", stage="S4", modes=[ToolMode.ACTIVE],
        purpose="Web server misconfiguration and dangerous default files",
        license="GPL-2.0", homepage="https://github.com/sullo/nikto",
        binaries=["nikto", "nikto.pl"], version_args=["-Version"],
    ),
    ToolSpec(
        name="wapiti", display="Wapiti", stage="S4", modes=[ToolMode.ACTIVE],
        purpose="Black-box web application scanner (crawl held to scope)",
        license="GPL-2.0", homepage="https://wapiti-scanner.github.io",
        binaries=["wapiti"],
    ),
    ToolSpec(
        name="sqlmap", display="sqlmap", stage="S5", modes=[ToolMode.ACTIVE],
        purpose="Confirms SQL injection candidates at level 1 / risk 1, detection only",
        license="GPL-2.0", homepage="https://sqlmap.org",
        binaries=["sqlmap"],
    ),
]

TOOLS_BY_NAME = {t.name: t for t in TOOLS}


def zap_settings() -> tuple[str, str]:
    return os.environ.get("WAPTRIX_ZAP_URL", "http://127.0.0.1:8090"), os.environ.get("WAPTRIX_ZAP_API_KEY", "")


def _status(spec: ToolSpec, **kwargs) -> ToolStatus:
    return ToolStatus(**spec.model_dump(exclude={"binaries", "version_args", "python_dist", "http_service"}), **kwargs)


async def _detect_zap(spec: ToolSpec) -> ToolStatus:
    url, key = zap_settings()
    try:
        headers = {"X-ZAP-API-Key": key} if key else {}  # header, never a query param: keeps the key out of logs
        async with httpx.AsyncClient(timeout=5.0, headers=headers) as client:
            resp = await client.get(f"{url}/JSON/core/view/version/")
        resp.raise_for_status()
        return _status(spec, available=True, version=resp.json().get("version"), location=url)
    except (httpx.HTTPError, ValueError) as exc:
        return _status(spec, available=False, location=url, detail=f"ZAP daemon not reachable: {type(exc).__name__}")


async def detect(spec: ToolSpec) -> ToolStatus:
    if spec.http_service:
        return await _detect_zap(spec)
    path = next((p for b in spec.binaries if (p := shutil.which(b))), None)
    if path is None:
        return _status(spec, available=False, detail=f"none of {', '.join(spec.binaries)} on PATH")
    if spec.python_dist:
        try:
            return _status(spec, available=True, version=metadata.version(spec.python_dist), location=path)
        except metadata.PackageNotFoundError:
            pass
    run = await run_tool(spec.name, [path, *spec.version_args], timeout=DETECT_TIMEOUT, max_output=64 * 1024)
    if run.error or run.timed_out:
        return _status(spec, available=False, location=path, detail=run.error or "version check timed out")
    match = _VERSION_RE.search(run.stdout + "\n" + run.stderr)
    return _status(spec, available=True, version=match.group(1) if match else None, location=path)


async def detect_all() -> list[ToolStatus]:
    return list(await asyncio.gather(*(detect(spec) for spec in TOOLS)))
