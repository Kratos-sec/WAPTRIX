"""OWASP Top 10 (2025) mapping loader."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

MAP_PATH = Path(__file__).with_name("owasp_2025_map.json")


@lru_cache(maxsize=1)
def load_mapping() -> dict[str, Any]:
    with MAP_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def get_rule(rule_id: str) -> dict[str, Any]:
    rules = load_mapping()["rules"]
    try:
        return rules[rule_id]
    except KeyError as exc:
        raise KeyError(f"rule {rule_id!r} is not defined in owasp_2025_map.json") from exc


def categories() -> dict[str, dict[str, Any]]:
    return load_mapping()["categories"]



@lru_cache(maxsize=1)
def _cwe_index() -> dict[str, list[str]]:
    """CWE -> OWASP 2025 ids. CWEs used by built-in rules take the union of those rules' categories."""
    from_rules: dict[str, list[str]] = {}
    for rule in load_mapping()["rules"].values():
        from_rules[rule["cwe"]] = list(dict.fromkeys([*from_rules.get(rule["cwe"], []), *rule["owasp"]]))
    with MAP_PATH.with_name("cwe_owasp_2025.json").open(encoding="utf-8") as handle:
        supplement: dict[str, list[str]] = json.load(handle)["cwe"]
    return {**supplement, **from_rules}


def normalize_cwe(value: str | int | None) -> str | None:
    """'79', 79, 'CWE-79', 'cwe-79' -> 'CWE-79'; None/0/-1/garbage -> None."""
    if value is None:
        return None
    text = str(value).strip().upper().removeprefix("CWE-")
    return f"CWE-{int(text)}" if text.isdigit() and int(text) > 0 else None


def owasp_for_cwe(cwe: str | None) -> list[str]:
    return list(_cwe_index().get(cwe, [])) if cwe else []
