"""External tool adapters, keyed by registry tool name.

Passive adapters only observe what a normal visitor would see; active adapters send probes or payloads
and run only when the audit explicitly opts into active mode (see AuditRequest.active).
"""

from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter
from app.tools.adapters.nikto import NiktoAdapter
from app.tools.adapters.nmap import NmapAdapter
from app.tools.adapters.nuclei import NucleiAdapter
from app.tools.adapters.retire import RetireAdapter
from app.tools.adapters.sqlmap import SqlmapAdapter
from app.tools.adapters.sslyze import SSLyzeAdapter
from app.tools.adapters.testssl import TestSSLAdapter
from app.tools.adapters.wapiti import WapitiAdapter
from app.tools.adapters.whatweb import WhatWebAdapter
from app.tools.adapters.zap import ZapActiveAdapter, ZapAdapter

PASSIVE_ADAPTERS: dict[str, type[ToolAdapter]] = {
    a.name: a for a in (WhatWebAdapter, SSLyzeAdapter, TestSSLAdapter, RetireAdapter, ZapAdapter)
}

# ZAP is in both: "zap" runs passive rules only, "zap-active" spiders and runs active scan rules.
ACTIVE_ADAPTERS: dict[str, type[ToolAdapter]] = {
    a.name: a for a in (NmapAdapter, NucleiAdapter, NiktoAdapter, WapitiAdapter, SqlmapAdapter, ZapActiveAdapter)
}

ALL_ADAPTERS: dict[str, type[ToolAdapter]] = {**PASSIVE_ADAPTERS, **ACTIVE_ADAPTERS}

__all__ = ["PASSIVE_ADAPTERS", "ACTIVE_ADAPTERS", "ALL_ADAPTERS",
           "AdapterContext", "AdapterResult", "ToolAdapter"]
