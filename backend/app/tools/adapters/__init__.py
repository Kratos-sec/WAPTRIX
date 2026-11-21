"""External passive tool adapters, keyed by registry tool name."""

from app.tools.adapters.base import AdapterContext, AdapterResult, ToolAdapter
from app.tools.adapters.retire import RetireAdapter
from app.tools.adapters.sslyze import SSLyzeAdapter
from app.tools.adapters.testssl import TestSSLAdapter
from app.tools.adapters.whatweb import WhatWebAdapter
from app.tools.adapters.zap import ZapAdapter

PASSIVE_ADAPTERS: dict[str, type[ToolAdapter]] = {
    a.name: a for a in (WhatWebAdapter, SSLyzeAdapter, TestSSLAdapter, RetireAdapter, ZapAdapter)
}

__all__ = ["PASSIVE_ADAPTERS", "AdapterContext", "AdapterResult", "ToolAdapter"]
