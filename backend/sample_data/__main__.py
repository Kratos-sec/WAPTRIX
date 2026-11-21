"""Regenerate sample_data/demo_audit.json:  python -m sample_data"""

import asyncio

from sample_data import build_demo_audit, write_demo

if __name__ == "__main__":
    audit = asyncio.run(build_demo_audit())
    path = write_demo(audit)
    print(
        f"Wrote {path} — {audit.summary.subdomains_total} subdomains, "
        f"{audit.summary.total_findings} findings, overall {audit.summary.overall_score}/100 ({audit.summary.grade})"
    )
