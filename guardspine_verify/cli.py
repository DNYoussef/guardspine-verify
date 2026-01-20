"""
Command-line interface for guardspine-verify.
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, verify_bundle


console = Console()


@click.command()
@click.argument("bundle_path", type=click.Path(exists=True))
@click.option("-v", "--verbose", is_flag=True, help="Show detailed output")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.version_option(__version__, prog_name="guardspine-verify")
def main(bundle_path: str, verbose: bool, output_format: str) -> None:
    """
    Verify a GuardSpine evidence bundle.

    BUNDLE_PATH: Path to the bundle file (.json or .zip)

    Exit codes:
      0 - Bundle verified successfully
      1 - Verification failed
      2 - Invalid input
    """
    path = Path(bundle_path)

    if output_format == "json":
        result = verify_bundle(path)
        output = {
            "verified": result.verified,
            "status": result.status,
            "hash_chain_status": result.hash_chain_status,
            "root_hash_status": result.root_hash_status,
            "content_hash_status": result.content_hash_status,
            "signature_status": result.signature_status,
            "errors": result.errors,
            "warnings": result.warnings,
            "verified_at": result.verified_at.isoformat(),
        }
        if verbose:
            output["details"] = result.details
        click.echo(json.dumps(output, indent=2))
        sys.exit(0 if result.verified else 1)

    # Text output
    console.print()
    console.print(
        Panel.fit(
            f"[bold]GuardSpine Verify v{__version__}[/bold]\n"
            f"Verifying: [cyan]{path.name}[/cyan]",
            border_style="blue",
        )
    )
    console.print()

    result = verify_bundle(path)

    # Status table
    table = Table(title="Verification Results", show_header=True)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    def status_icon(status: str) -> str:
        if status == "verified":
            return "[green]PASS[/green]"
        elif status == "mismatch":
            return "[red]FAIL[/red]"
        else:
            return "[yellow]UNKNOWN[/yellow]"

    table.add_row(
        "Hash Chain",
        status_icon(result.hash_chain_status),
        _get_detail(result.details.get("hash_chain", {})),
    )
    table.add_row(
        "Root Hash",
        status_icon(result.root_hash_status),
        _get_detail(result.details.get("root_hash", {})),
    )
    table.add_row(
        "Content Hashes",
        status_icon(result.content_hash_status),
        _get_detail(result.details.get("content_hashes", {})),
    )
    table.add_row(
        "Signatures",
        status_icon(result.signature_status),
        _get_detail(result.details.get("signatures", {})),
    )

    console.print(table)
    console.print()

    # Errors
    if result.errors:
        console.print("[red bold]Errors:[/red bold]")
        for error in result.errors:
            console.print(f"  [red]x[/red] {error}")
        console.print()

    # Warnings
    if result.warnings:
        console.print("[yellow bold]Warnings:[/yellow bold]")
        for warning in result.warnings:
            console.print(f"  [yellow]![/yellow] {warning}")
        console.print()

    # Overall result
    if result.verified:
        console.print(
            Panel(
                "[green bold]BUNDLE VERIFIED[/green bold]\n\n"
                "The evidence bundle integrity has been verified.\n"
                "All hash chains, content hashes, and signatures are valid.",
                border_style="green",
            )
        )
        sys.exit(0)
    else:
        console.print(
            Panel(
                "[red bold]VERIFICATION FAILED[/red bold]\n\n"
                "The evidence bundle failed integrity checks.\n"
                "See errors above for details.",
                border_style="red",
            )
        )
        sys.exit(1)


def _get_detail(detail: dict) -> str:
    """Extract a summary detail string."""
    if "entries_checked" in detail:
        return f"{detail['entries_checked']} entries checked"
    if "items_checked" in detail:
        return f"{detail['items_checked']} items checked"
    if "signatures_checked" in detail:
        return f"{detail['signatures_checked']}/{detail.get('signatures_total', '?')} signatures"
    if detail.get("warnings"):
        return detail["warnings"][0]
    return ""


if __name__ == "__main__":
    main()
