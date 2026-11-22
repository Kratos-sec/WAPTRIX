"""WAPTrix command line interface.

    python -m app.cli audit --subdomains subdomains.txt --auth-ref ENG-2026-001 --out ./reports
    python -m app.cli demo --out ./demo_reports
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from app.compliance import load_mapping
from app.compliance.scorer import cvss31_base_score
from app.engine.passive_auditor import PassiveAuditor
from app.engine.stages import RunLog
from app.engine.scope_guard import ScopeError, build_scope
from app.models.audit import AuditRequest, AuditResult, RunEvent
from app.reporting.exporter import FORMATS, write_reports

app = typer.Typer(
    name="waptrix",
    help="WAPTrix — strictly passive web application security auditing & OWASP Top 10 (2025) compliance.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red", "N/A": "dim"}
_STATUS_STYLE = {"pass": "[green]PASS[/]", "warning": "[yellow]WARN[/]", "fail": "[red]FAIL[/]", "manual_review": "[dim]MANUAL[/]"}


def _parse_formats(value: str) -> list[str]:
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    if "all" in formats:
        return list(FORMATS)
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise typer.BadParameter(f"unknown format(s) {', '.join(unknown)}; choose from {', '.join(FORMATS)} or 'all'")
    return formats


def _read_targets(path: Path) -> list[str]:
    if not path.exists():
        raise typer.BadParameter(f"{path} does not exist")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]


_STAGE_STYLE = {"completed": "[green]done[/]", "skipped": "[dim]skipped[/]", "failed": "[red]failed[/]"}


def _print_summary(audit: AuditResult) -> None:
    summary = audit.summary
    grade_style = _GRADE_STYLE.get(summary.grade, "")
    console.print()
    console.rule(f"[bold]WAPTrix passive audit[/] · {audit.authorization_ref}")
    console.print(
        f"Overall compliance score: [bold]{summary.overall_score if summary.overall_score is not None else '—'}/100[/] "
        f"grade [{grade_style}]{summary.grade}[/] · {summary.subdomains_reachable}/{summary.subdomains_total} reachable · "
        f"{summary.total_findings} findings "
        f"([red]{summary.severity_counts.get('high', 0)} high[/], [dark_orange]{summary.severity_counts.get('medium', 0)} medium[/], "
        f"[yellow]{summary.severity_counts.get('low', 0)} low[/], [blue]{summary.severity_counts.get('info', 0)} info[/])"
        + (f" · [dim]{summary.total_retest} awaiting re-test[/]" if summary.total_retest else "")
    )

    table = Table(show_lines=False, header_style="bold cyan")
    table.add_column("Subdomain")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("H/M/L/I", justify="center")
    for cat_id in [c.id for c in summary.categories]:
        table.add_column(cat_id.split(":")[0], justify="center")
    for sub in audit.subdomains:
        counts = sub.severity_counts
        table.add_row(
            sub.subdomain + ("" if sub.reachable else f"\n[dim]{(sub.error or '')[:60]}[/]"),
            f"[{_GRADE_STYLE.get(sub.grade, '')}]{sub.grade}[/]",
            str(sub.score) if sub.score is not None else "—",
            f"{counts.get('high', 0) + counts.get('critical', 0)}/{counts.get('medium', 0)}/{counts.get('low', 0)}/{counts.get('info', 0)}",
            *[_STATUS_STYLE[c.status.value] for c in sub.categories],
        )
    console.print(table)
    if audit.stages:
        stages = Table(title="Workflow stages", show_lines=False, header_style="bold cyan", title_justify="left")
        for col in ("Stage", "Name", "Status", "Hosts", "Runs", "Time", "Counts"):
            stages.add_column(col, justify="right" if col in ("Hosts", "Runs", "Time") else "left")
        for st in audit.stages:
            stages.add_row(st.stage.value, st.name, _STAGE_STYLE.get(st.status.value, st.status.value),
                           str(st.hosts or "—"), str(st.runs), f"{st.duration_ms / 1000:.1f}s",
                           ", ".join(f"{k} {v}" for k, v in st.counts.items()))
        console.print(stages)
    if audit.scope_rejections:
        console.print("[yellow]Rejected by scope guard:[/]")
        for rejection in audit.scope_rejections:
            console.print(f"  • {rejection.input} — {rejection.reason}")


def _write(audit: AuditResult, out: Path, formats: list[str], subdomain: Optional[str]) -> None:
    written = write_reports(audit, out, formats, subdomain=subdomain)
    console.print()
    console.print("[bold]Reports written:[/]")
    for path, note in written:
        console.print(f"  • {path}" + (f"  [yellow]({note})[/]" if note else ""))


@app.command()
def audit(
    subdomains: Path = typer.Option(..., "--subdomains", "-s", help="Text file with one subdomain per line"),
    auth_ref: str = typer.Option(..., "--auth-ref", "-a", help="Authorization / engagement reference, e.g. ENG-2026-001"),
    out: Path = typer.Option(Path("./reports"), "--out", "-o", help="Output directory for reports"),
    formats: str = typer.Option("all", "--format", "-f", help=f"Comma-separated: {', '.join(FORMATS)} or 'all'"),
    scope_domain: list[str] = typer.Option([], "--scope-domain", help="Restrict targets to these apex domains (repeatable)"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", min=1, max=20, help="Subdomains audited in parallel"),
    rate: float = typer.Option(2.0, "--rate", "-r", min=0.1, max=10.0, help="Max requests per second per host"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", min=1, max=60, help="Per-request timeout (s)"),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow targets resolving to private/reserved IPs"),
    no_metadata: bool = typer.Option(False, "--no-metadata", help="Skip /robots.txt and /.well-known/security.txt"),
    subdomain: Optional[str] = typer.Option(None, "--only", help="Export reports for this single subdomain only"),
    save: bool = typer.Option(True, "--save/--no-save", help="Persist the audit in the local SQLite database"),
    tool: list[str] = typer.Option(
        [], "--tool", help="External passive tool to add (repeatable): whatweb, sslyze, testssl, retire, zap, or 'all'"
    ),
    active: bool = typer.Option(
        False, "--active", help="Opt in to ACTIVE scanning (sends probes/payloads); needs --scope-domain and active tools"
    ),
    active_tool: list[str] = typer.Option(
        [], "--active-tool", help="Active tool to add (repeatable): nmap, nuclei, nikto, wapiti, sqlmap, or 'all'"
    ),
    tool_timeout: float = typer.Option(600.0, "--tool-timeout", min=10, max=3600, help="Per-tool, per-host limit (s)"),
    retest_rounds: int = typer.Option(
        1, "--retest-rounds", min=0, max=3, help="Bounded S5→S3 re-test rounds for below-threshold candidates"
    ),
    max_endpoints: int = typer.Option(
        5, "--max-endpoints", min=1, max=50, help="Parameterised endpoints per host for per-endpoint engines (sqlmap)"
    ),
) -> None:
    """Run a passive audit (optionally with opt-in active tools) against authorized subdomains."""
    from pydantic import ValidationError

    from app.tools.adapters import ACTIVE_ADAPTERS, PASSIVE_ADAPTERS

    fmt_list = _parse_formats(formats)
    targets = _read_targets(subdomains)
    tools = list(PASSIVE_ADAPTERS) if "all" in [t.lower() for t in tool] else tool
    active_tools = list(ACTIVE_ADAPTERS) if "all" in [t.lower() for t in active_tool] else active_tool
    try:
        request = AuditRequest(
            subdomains=targets,
            authorization_ref=auth_ref,
            scope_domains=scope_domain,
            concurrency=concurrency,
            requests_per_second=rate,
            timeout=timeout,
            allow_private=allow_private,
            include_metadata=not no_metadata,
            tools=tools,
            active=active,
            active_tools=active_tools,
            tool_timeout=tool_timeout,
            retest_rounds=retest_rounds,
            max_endpoints=max_endpoints,
        )
    except ValidationError as exc:
        console.print(f"[bold red]Invalid options:[/] {exc.errors()[0]['msg']}")
        raise typer.Exit(code=2) from exc
    try:
        decision = build_scope(targets, auth_ref, scope_domains=scope_domain, allow_private=allow_private)
    except ScopeError as exc:
        console.print(f"[bold red]Scope error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    active_on = request.active and bool(request.active_tools)
    console.print(
        f"[bold cyan]WAPTrix[/] {'[bold red]ACTIVE[/]' if active_on else 'passive'} audit · "
        f"authorization [bold]{auth_ref}[/] · {len(decision.targets)} target(s) · {rate:g} req/s/host · "
        + ("sends probes/payloads" if active_on else "GET + TLS handshakes only")
        + (f" · passive tools: {', '.join(request.tools)}" if request.tools else "")
        + (f" · active tools: {', '.join(request.active_tools)}" if active_on else "")
    )
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing", total=len(decision.targets))

        def on_progress(done: int, total: int, current: str) -> None:
            progress.update(task, completed=done, description=f"Audited {current}")

        def on_event(event: RunEvent) -> None:
            if event.status.value == "started" and event.subdomain:
                again = f" (re-test {event.round})" if event.round else ""
                progress.update(task, description=f"{event.stage.value} {event.stage.label}{again} · {event.subdomain}")

        result = asyncio.run(PassiveAuditor(request, progress=on_progress, run_log=RunLog(sink=on_event)).run())

    _print_summary(result)
    if save:
        from app.db import AuditStore

        AuditStore().save(result)
        console.print(f"[dim]Saved audit {result.id} to local database.[/]")
    _write(result, out, fmt_list, subdomain)


@app.command()
def demo(
    out: Path = typer.Option(Path("./demo_reports"), "--out", "-o", help="Output directory for reports"),
    formats: str = typer.Option("all", "--format", "-f", help=f"Comma-separated: {', '.join(FORMATS)} or 'all'"),
    subdomain: Optional[str] = typer.Option(None, "--only", help="Export reports for this single subdomain only"),
    regenerate: bool = typer.Option(False, "--regenerate", help="Rebuild the dataset from the engine instead of the bundled JSON"),
    save: bool = typer.Option(True, "--save/--no-save", help="Persist the demo audit in the local SQLite database"),
) -> None:
    """Run the built-in offline 5-subdomain demo audit (no network access)."""
    from sample_data import build_demo_audit, load_demo_audit, write_demo

    fmt_list = _parse_formats(formats)
    if regenerate:
        result = asyncio.run(build_demo_audit())
        write_demo(result)
    else:
        result = load_demo_audit()
    _print_summary(result)
    if save:
        from app.db import AuditStore

        AuditStore().save(result)
    _write(result, out, fmt_list, subdomain)


@app.command("rules")
def list_rules() -> None:
    """List every passive rule with its OWASP Top 10 (2025), CWE, WSTG and CVSS mapping."""
    table = Table(header_style="bold cyan")
    for column in ("Rule", "Severity", "OWASP 2025", "CWE", "WSTG", "CVSS", "Title"):
        table.add_column(column)
    for rule_id, meta in load_mapping()["rules"].items():
        table.add_row(
            rule_id,
            meta["severity"],
            ", ".join(meta["owasp"]),
            meta["cwe"],
            meta.get("wstg") or "—",
            f"{cvss31_base_score(meta['cvss_vector']):.1f}",
            meta["title"],
        )
    console.print(table)


@app.command("tools")
def list_tools() -> None:
    """Show which external security tools are installed, with versions."""
    from app.tools import detect_all

    table = Table(header_style="bold cyan")
    for col in ("Tool", "Stage", "Modes", "Status", "Version", "Location / detail"):
        table.add_column(col)
    for status in asyncio.run(detect_all()):
        table.add_row(
            status.display,
            status.stage,
            ", ".join(m.value for m in status.modes),
            "[green]available[/]" if status.available else "[red]missing[/]",
            status.version or "—",
            status.location if status.available else (status.detail or status.location or ""),
        )
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(8000, help="Port"),
    reload: bool = typer.Option(False, help="Auto-reload on code changes"),
) -> None:
    """Start the REST API (and the built dashboard, if frontend/dist exists)."""
    import uvicorn

    uvicorn.run("app.main:app", host=host, port=port, reload=reload)


lab_app = typer.Typer(help="Benchmark lab: collect runs against the vulnerable apps and score them (Table VII).",
                      no_args_is_help=True)
app.add_typer(lab_app, name="lab")


def _lab_dir(value: Optional[Path]) -> Path:
    import os

    if value is not None:
        return value
    if os.environ.get("WAPTRIX_LAB_DIR"):
        return Path(os.environ["WAPTRIX_LAB_DIR"])
    if Path("/lab/targets.json").exists():  # mounted by docker-compose.lab.yml
        return Path("/lab")
    return Path(__file__).resolve().parents[2] / "lab"


@lab_app.command("collect")
def lab_collect(
    out: Path = typer.Option(..., "--out", "-o", help="Directory for run records (<app>-r<k>.json)"),
    app_id: list[str] = typer.Option([], "--app", help="Lab app id (repeatable); default: every app in targets.json"),
    reps: int = typer.Option(3, "--reps", min=1, max=10, help="Repetitions per app (the paper keeps the median of 3)"),
    tool_timeout: float = typer.Option(1800.0, "--tool-timeout", min=10, max=3600, help="Per-tool, per-host limit (s)"),
    lab: Optional[Path] = typer.Option(None, "--lab", help="Lab directory holding targets.json and ground truth"),
) -> None:
    """Run the full ACTIVE workflow against the lab apps. Only hosts on the private lab network are scanned."""
    from app.evaluation.harness import load_config, run_collect

    config = load_config(_lab_dir(lab))
    console.print(f"[bold red]ACTIVE[/] benchmark collection · {', '.join(app_id) or 'all apps'} · {reps} repetition(s)")
    try:
        paths = run_collect(config, out, apps=app_id or None, reps=reps, tool_timeout=tool_timeout,
                            log=lambda m: console.print(f"[dim]{m}[/]"))
    except (RuntimeError, KeyError) as exc:
        console.print(f"[bold red]Lab error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"Wrote {len(paths)} run record(s) to {out}")


@lab_app.command("evaluate")
def lab_evaluate(
    runs: Path = typer.Option(..., "--runs", "-r", help="Directory of run records from 'lab collect'"),
    out: Path = typer.Option(..., "--out", "-o", help="Directory for results.json, table.md and table.csv"),
    lab: Optional[Path] = typer.Option(None, "--lab", help="Lab directory holding targets.json and ground truth"),
) -> None:
    """Score collected runs against ground truth: per engine, naive union, WAPTrix, and leave-one-app-out."""
    from app.evaluation.harness import evaluate, load_config, load_runs, write_results

    config = load_config(_lab_dir(lab))
    records = load_runs(runs)
    if not records:
        console.print(f"[bold red]No run records in {runs}[/]")
        raise typer.Exit(code=2)
    results = evaluate(config, records)
    table = Table(title="Consolidated detection performance", header_style="bold cyan", title_justify="left")
    for col in ("Engine", "TP", "FP", "FN", "Precision", "Recall", "F1", "Min"):
        table.add_column(col, justify="left" if col == "Engine" else "right")
    for row in results["table"]:
        table.add_row(row["system"] + ("" if row["ran"] else " [dim](did not run)[/]"), str(row["tp"]), str(row["fp"]),
                      str(row["fn"]), f"{row['precision']:.3f}", f"{row['recall']:.3f}", f"{row['f1']:.3f}",
                      "—" if row["mean_scan_minutes"] is None else f"{row['mean_scan_minutes']:.1f}")
    console.print(table)
    partial = [a for a, g in results["ground_truth"].items() if g["partial"]]
    if partial:
        console.print(f"[yellow]Ground truth is partial for: {', '.join(partial)} — not yet comparable with Table VII.[/]")
    for path in write_results(results, out):
        console.print(f"  • {path}")


if __name__ == "__main__":
    app()
