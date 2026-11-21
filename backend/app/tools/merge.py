"""Merge external tool findings into a subdomain's built-in findings.

Rule of thumb until the correlation engine lands: an issue counts once per rule per host.
- If the host already has a finding for that rule (from built-in checks or an earlier tool), the tool is
  recorded as corroborating every existing instance, and its own instance is dropped. Scores do not
  change just because more engines agree.
- Otherwise the tool's finding is added, so tools contribute coverage the built-in checks lack.
"""

from __future__ import annotations

from app.models.finding import PassiveFinding

# Tools that cannot tell session cookies apart report the generic rule; a built-in finding for the
# stricter variant on the same host already covers it.
EQUIVALENT_RULES = {"CKE-NO-HTTPONLY": ("CKE-SESSION-NO-HTTPONLY",)}


def merge_findings(existing: list[PassiveFinding], incoming: list[PassiveFinding]) -> list[PassiveFinding]:
    merged = list(existing)
    by_rule: dict[str, list[PassiveFinding]] = {}
    for finding in merged:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    added_by: dict[str, str] = {}  # rule_id -> tool whose instances were added for that rule
    seen_ids = {f.id for f in merged}
    for finding in incoming:
        tool = finding.sources[0]
        current = by_rule.get(finding.rule_id) or next(
            (by_rule[alt] for alt in EQUIVALENT_RULES.get(finding.rule_id, ()) if alt in by_rule), None)
        if current and added_by.get(current[0].rule_id) != tool:
            for other in current:
                other.sources = list(dict.fromkeys([*other.sources, *finding.sources]))
                other.tool_refs = list(dict.fromkeys([*other.tool_refs, *finding.tool_refs]))
            continue
        if finding.id in seen_ids:
            continue
        # First tool to report this rule on the host; keep all its instances (e.g. one per library).
        merged.append(finding)
        seen_ids.add(finding.id)
        added_by[finding.rule_id] = tool
        by_rule.setdefault(finding.rule_id, []).append(finding)
    return merged
