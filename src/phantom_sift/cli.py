"""Phantom SIFT CLI — Entry point for the forensic agent.

Usage:
    phantom-sift analyze --case /path/to/evidence.dd
    phantom-sift analyze --case /path/to/memory.vmem --type memory
    phantom-sift doctor
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .config import get_settings

console = Console()


@click.group()
@click.version_option(package_name="phantom-sift")
def main() -> None:
    """👻 Phantom SIFT — Autonomous DFIR Agent."""
    pass


@main.command()
@click.option("--case", required=True, type=click.Path(exists=True), help="Path to evidence file")
@click.option(
    "--type",
    "evidence_type",
    type=click.Choice(["disk", "memory", "logs", "pcap"]),
    default="disk",
    help="Type of evidence",
)
@click.option("--max-iterations", type=int, default=None, help="Override max agent iterations")
@click.option("--dry-run", is_flag=True, help="Validate setup without running analysis")
def analyze(
    case: str,
    evidence_type: str,
    max_iterations: int | None,
    dry_run: bool,
) -> None:
    """Analyze forensic evidence autonomously."""
    settings = get_settings()

    if not settings.anthropic_api_key and not dry_run:
        console.print("[red]ERROR: ANTHROPIC_API_KEY not set. See .env.example[/red]")
        sys.exit(1)

    case_path = Path(case)
    iterations = max_iterations or settings.agent_max_iterations

    console.print(f"\n[bold cyan]👻 Phantom SIFT[/bold cyan] — Autonomous DFIR Agent")
    console.print(f"   Case: {case_path.name}")
    console.print(f"   Type: {evidence_type}")
    console.print(f"   Max iterations: {iterations}")
    console.print(f"   Model: {settings.agent_model}")

    if settings.cloudflare_gateway_base_url:
        console.print(f"   AI Gateway: [green]✓[/green] Cloudflare (logging enabled)")
    else:
        console.print(f"   AI Gateway: [yellow]○[/yellow] Direct (no token logging)")

    if dry_run:
        console.print("\n[yellow]DRY RUN — validating setup only[/yellow]")
        return

    console.print("\n[bold]Starting analysis...[/bold]\n")

    from .agent.loop import AgentLoop

    agent = AgentLoop(settings=settings)
    result = agent.run(case_path=case_path, evidence_type=evidence_type, max_iterations=iterations)

    if result.success:
        console.print(f"\n[green]✓ Analysis complete[/green] — {len(result.findings)} findings")
        console.print(f"  Iterations: {result.iterations_used}/{iterations}")
        console.print(f"  Self-corrections: {result.self_corrections}")
        console.print(f"  Log: {settings.execution_log_path}")
    else:
        console.print(f"\n[red]✗ Analysis failed[/red]: {result.error}")
        sys.exit(1)


@main.command()
def doctor() -> None:
    """Validate environment and tool availability."""
    settings = get_settings()
    console.print("\n[bold cyan]👻 Phantom SIFT Doctor[/bold cyan]\n")

    checks = []

    # Check Python version
    py_version = sys.version_info
    checks.append(("Python 3.11+", py_version >= (3, 11)))

    # Check API key
    checks.append(("Anthropic API key", bool(settings.anthropic_api_key)))

    # Check Cloudflare
    checks.append(("Cloudflare AI Gateway", bool(settings.cloudflare_gateway_base_url)))

    # Check evidence path
    checks.append(("Evidence mount path exists", settings.evidence_mount_path.exists()))

    # Check SIFT tools availability
    from .mcp_server.tools import check_tool_availability

    sift_tools = check_tool_availability()
    checks.append(("SIFT tools available", sift_tools["available_count"] > 0))

    # Print results
    all_pass = True
    for name, passed in checks:
        icon = "[green]✓[/green]" if passed else "[red]✗[/red]"
        console.print(f"  {icon} {name}")
        if not passed:
            all_pass = False

    if sift_tools["available_count"] > 0:
        console.print(f"\n  Tools found: {sift_tools['available_count']}/{sift_tools['total']}")
        for tool in sift_tools.get("missing", []):
            console.print(f"    [yellow]○ {tool} not found[/yellow]")

    if all_pass:
        console.print("\n[green]All checks passed. Ready to find evil.[/green]")
    else:
        console.print("\n[yellow]Some checks failed. See .env.example for configuration.[/yellow]")


if __name__ == "__main__":
    main()
