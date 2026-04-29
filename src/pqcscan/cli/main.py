from __future__ import annotations

import click

from pqcscan import __version__
from pqcscan.cli.daemon_cmd import daemon_cmd
from pqcscan.cli.export import export_cmd
from pqcscan.cli.scan import scan_cmd, scans_cmd, status_cmd


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """Post-Quantum Cryptography readiness scanner."""


@cli.command("version")
def version_cmd() -> None:
    """Print pqcscan version."""
    click.echo(f"pqcscan {__version__}")


cli.add_command(scan_cmd, name="scan")
cli.add_command(scans_cmd, name="scans")
cli.add_command(status_cmd, name="status")
cli.add_command(daemon_cmd, name="daemon")
cli.add_command(export_cmd, name="export")
