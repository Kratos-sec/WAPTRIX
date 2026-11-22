"""Engine reliability weights, capability tags and voting parameters (paper Section III-D).

This module answers three questions the voting model (`app.correlation.voting`) asks of every finding:
  * how reliable is each engine (``weight`` w_i),
  * which engines are *capable* of a finding's class (``detects`` -> the applicable set E), and
  * which engines actively *confirm* a class (``confirms`` -> the v(f) bonus).

A finding is reduced to a single capability *tag* so engines can be compared on the same axis. Built-in
rules carry a ``check`` in ``owasp_2025_map.json`` which is the tag directly; tool-only alerts
(``<TOOL>-<id>``) are tagged from their CWE, then from the emitting tool's default.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.compliance import load_mapping

_PROFILE_PATH = Path(__file__).with_name("engine_profiles.json")

# A built-in finding's `check` is already a tag; these tags extend the vocabulary for tool-only alerts.
# Rule ids whose `check` does not describe the real class get an explicit tag here.
RULE_TAG_OVERRIDE = {"JS-VULNERABLE-LIBRARY": "libraries"}

# Rules where several distinct findings per endpoint are legitimate (e.g. one row per vulnerable library),
# so the canonical key must keep them apart by evidence instead of collapsing them into one.
MULTI_INSTANCE_RULES = {"JS-VULNERABLE-LIBRARY"}

# A generic rule a tool cannot refine into the stricter variant the built-in checks emit; both describe
# the same defect, so they share a canonical class and vote together.
EQUIVALENT_RULES = {"CKE-NO-HTTPONLY": "CKE-SESSION-NO-HTTPONLY"}

# CWE -> capability tag for tool-only alerts that carry no WAPTrix rule mapping.
CWE_TAG = {
    "CWE-89": "injection", "CWE-79": "injection", "CWE-78": "injection", "CWE-94": "injection",
    "CWE-611": "injection", "CWE-918": "injection", "CWE-90": "injection", "CWE-91": "injection",
    "CWE-200": "disclosure", "CWE-209": "disclosure", "CWE-532": "disclosure", "CWE-538": "disclosure",
    "CWE-1395": "libraries", "CWE-937": "libraries", "CWE-1104": "libraries",
    "CWE-693": "headers",
    "CWE-264": "cors_cache", "CWE-942": "cors_cache",  # cross-domain / permissive-CORS misconfiguration
    "CWE-311": "transport_tls", "CWE-319": "transport_tls",  # cleartext transmission / site served over HTTP
    "CWE-497": "metadata",  # timestamp / internal-value disclosure: trivial info leakage
}

# Fallback tag per tool when neither the rule map nor the CWE resolves a class.
TOOL_DEFAULT_TAG = {
    "nikto": "misconfig", "nuclei": "misconfig", "wapiti": "injection", "sqlmap": "injection",
    "zap": "misconfig", "zap-active": "misconfig", "nmap": "ports", "whatweb": "tech", "retire": "libraries",
}
DEFAULT_TAG = "misconfig"


@lru_cache(maxsize=1)
def _profiles() -> dict[str, Any]:
    with _PROFILE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _env_float(name: str, fallback: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        return float(raw)
    except ValueError:
        return fallback


def tau() -> float:
    """Admission threshold (default 0.55); overridable with WAPTRIX_VOTE_TAU for calibration runs."""
    return _env_float("WAPTRIX_VOTE_TAU", _profiles()["tau"])


def gamma() -> float:
    """Active-confirmation bonus (default 0.15); overridable with WAPTRIX_VOTE_GAMMA."""
    return _env_float("WAPTRIX_VOTE_GAMMA", _profiles()["gamma"])


def certainty(confidence: str) -> float:
    """Normalised certainty s_i(f) in [0, 1] from a Burp-style confidence label."""
    return _profiles()["certainty"].get(confidence, 0.45)


def _engine(name: str) -> dict[str, Any]:
    return _profiles()["engines"].get(name, {})


def weight(engine: str) -> float:
    """Per-engine reliability weight w_i; unknown engines get a cautious default."""
    return float(_engine(engine).get("weight", 0.5))


def detects(engine: str) -> set[str]:
    return set(_engine(engine).get("detects", ()))


def confirms(engine: str, tag: str) -> bool:
    return tag in _engine(engine).get("confirms", ())


def known_engines() -> set[str]:
    return set(_profiles()["engines"])


@lru_cache(maxsize=1)
def _builtin_checks() -> dict[str, str]:
    return {rid: rule.get("check", DEFAULT_TAG) for rid, rule in load_mapping()["rules"].items()}


def is_builtin_rule(rule_id: str) -> bool:
    """True for a WAPTrix rule defined in owasp_2025_map.json (as opposed to a tool-only alert)."""
    return rule_id in _builtin_checks()


def tag_for(rule_id: str, cwe: str | None) -> str:
    """Capability tag for a finding, from its rule mapping, CWE, or emitting tool."""
    if rule_id in RULE_TAG_OVERRIDE:
        return RULE_TAG_OVERRIDE[rule_id]
    builtin = _builtin_checks().get(rule_id)
    if builtin is not None:
        return builtin
    if cwe and cwe in CWE_TAG:
        return CWE_TAG[cwe]
    tool = rule_id.split("-", 1)[0].lower()
    return TOOL_DEFAULT_TAG.get(tool, DEFAULT_TAG)
