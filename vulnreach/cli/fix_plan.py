"""vulnreach fix-plan — show which upgrades remove reachable CVEs."""

import json

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _markdown(plan: list) -> str:
    if not plan:
        return "_No reachable CVEs with available fixes found._"
    lines = ["## VulnReach Fix Plan", ""]
    for item in plan:
        pkg = item.get("package", "?")
        cur = item.get("current_version", "?")
        fix = item.get("upgrade_to", "?")
        cves = item.get("reachable_cves_removed") or []
        cve_str = ", ".join(str(c) for c in cves) if cves else "—"
        lines.append(f"- [ ] Upgrade `{pkg}` {cur} → {fix} — removes {len(cves)} reachable CVE(s): {cve_str}")
    return "\n".join(lines)


def _table(plan: list) -> None:
    if not plan:
        console.print("[dim]No reachable CVEs with available fixes.[/dim]")
        return
    t = Table(title="Fix Plan", show_lines=True)
    t.add_column("Package", style="cyan")
    t.add_column("Current", style="dim")
    t.add_column("Upgrade to", style="green")
    t.add_column("Reachable CVEs removed", style="red")
    t.add_column("Risk score", justify="right")
    for item in plan:
        cves = item.get("reachable_cves_removed") or []
        t.add_row(
            item.get("package", "?"),
            item.get("current_version", "?"),
            item.get("upgrade_to") or "no fix",
            "\n".join(str(c) for c in cves) if cves else "—",
            str(round(item.get("risk_score", 0), 1)),
        )
    console.print(t)


@click.command()
@click.option("--scan-id", required=True, help="Scan ID to generate a fix plan for.")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json", "markdown"], case_sensitive=False),
    show_default=True,
    help="Output format.",
)
@click.pass_context
def fix_plan(ctx: click.Context, scan_id: str, fmt: str) -> None:
    """Show which package upgrades remove reachable CVEs."""
    mode = ctx.obj.get("mode", "local")

    if mode == "client":
        from vulnreach.client import VulnReachClient
        client = VulnReachClient(ctx.obj["url"], ctx.obj.get("token"))
        data = client.get_fix_plan(scan_id)
        plan = data.get("fix_plan") or []
    else:
        from storage import get_repository
        from api.fix_plan import build_fix_plan
        storage = get_repository()
        scan = storage.get_scan(scan_id)
        if not scan:
            raise click.ClickException(f"Scan {scan_id!r} not found.")
        plan = build_fix_plan(scan)

    if fmt == "json":
        click.echo(json.dumps(plan, indent=2))
    elif fmt == "markdown":
        click.echo(_markdown(plan))
    else:
        _table(plan)
