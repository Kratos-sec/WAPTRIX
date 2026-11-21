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
