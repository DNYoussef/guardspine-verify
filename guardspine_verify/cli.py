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
@click.option(
    "-k",
    "--public-key",
    "public_key_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to PEM public key for cryptographic signature verification",
)
@click.version_option(__version__, prog_name="guardspine-verify")
def main(bundle_path: str, verbose: bool, output_format: str, public_key_path: str | None) -> None:
    """
    Verify a GuardSpine evidence bundle.

    BUNDLE_PATH: Path to the bundle file (.json or .zip)

    Exit codes:
      0 - Bundle verified successfully
      1 - Verification failed
      2 - Invalid input

    Examples:
      guardspine-verify report.json
      guardspine-verify report.json --public-key signer.pub
      guardspine-verify bundle.zip -k signer.pub --verbose
    """
    path = Path(bundle_path)

    # Load and validate public key if provided
    public_key_pem: bytes | None = None
    if public_key_path:
        try:
            public_key_pem = Path(public_key_path).read_bytes()
        except OSError as e:
            console.print(f"[red]Error reading public key file: {e}[/red]")
            sys.exit(2)
        if not public_key_pem.strip().startswith(b"-----BEGIN"):
            console.print("[red]Error: Public key file does not appear to be PEM-encoded.[/red]")
            sys.exit(2)

    if output_format == "json":
        result = verify_bundle(path, public_key_pem=public_key_pem)
        output = {
            "verified": result.verified,
            "status": result.status,
            "hash_chain_status": result.hash_chain_status,
            "root_hash_status": result.root_hash_status,
            "content_hash_status": result.content_hash_status,
            "signature_status": result.signature_status,
            "cryptographically_verified": result.details.get("signatures", {}).get("cryptographically_verified", False),
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
    key_info = f"\nPublic Key: [cyan]{Path(public_key_path).name}[/cyan]" if public_key_path else ""
    console.print(
        Panel.fit(
            f"[bold]GuardSpine Verify v{__version__}[/bold]\n"
            f"Verifying: [cyan]{path.name}[/cyan]{key_info}",
            border_style="blue",
        )
    )
    console.print()

    result = verify_bundle(path, public_key_pem=public_key_pem)

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
    crypto_verified = result.details.get("signatures", {}).get("cryptographically_verified", False)
    if result.verified:
        if crypto_verified:
            msg = (
                "[green bold]BUNDLE VERIFIED (CRYPTOGRAPHICALLY)[/green bold]\n\n"
                "The evidence bundle integrity has been verified.\n"
                "All hash chains, content hashes, and [bold]cryptographic signatures[/bold] are valid."
            )
        else:
            msg = (
                "[green bold]BUNDLE VERIFIED (FORMAT ONLY)[/green bold]\n\n"
                "The evidence bundle format and hash integrity verified.\n"
                "[yellow]Note: Signatures validated format only. Provide --public-key for cryptographic verification.[/yellow]"
            )
        console.print(Panel(msg, border_style="green"))
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
        crypto_count = detail.get("crypto_verified_count", 0)
        total = detail.get("signatures_total", "?")
        if crypto_count > 0:
            return f"{crypto_count}/{total} cryptographically verified"
        return f"{detail['signatures_checked']}/{total} format validated"
    if detail.get("warnings"):
        return detail["warnings"][0]
    return ""


if __name__ == "__main__":
    main()
