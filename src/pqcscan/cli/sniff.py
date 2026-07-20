from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from pqcscan.probes._base import SniffConfig
from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON to stdout.")
@click.option(
    "--iface", default=None,
    help="Network interface to capture on (default: all interfaces).",
)
@click.option(
    "--seconds", type=float, default=15.0, show_default=True,
    help="Capture window length in seconds.",
)
@click.option(
    "--max-packets", type=int, default=20000, show_default=True,
    help="Stop after this many captured frames.",
)
def sniff_cmd(
    db: Path | None, as_json: bool,
    iface: str | None, seconds: float, max_packets: int,
) -> None:
    """Live passive TLS capture (Linux, needs CAP_NET_RAW/root).

    Opens a raw AF_PACKET socket, listens for a bounded window, and classifies
    the KEX / cipher / certificate crypto seen on the wire. Skips gracefully
    when run without privilege or off Linux.
    """
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo(db_path)
    repo.init_schema()
    bus = EventBus()
    registry = default_registry()
    # The runner caps each probe at per_probe_timeout_s (default 30s). A capture
    # window longer than that would otherwise be cut short, so give the runner a
    # timeout that clears the window plus margin for parse/emit.
    runner = ProbeRunner(
        registry=registry, repo=repo, bus=bus,
        per_probe_timeout_s=max(30.0, seconds + 15.0),
    )

    scan_id = asyncio.run(runner.run(
        mode=current_mode(),
        available_capabilities=detect_capabilities(),
        sniff=SniffConfig(interface=iface, seconds=seconds, max_packets=max_packets),
    ))
    findings = repo.list_findings(scan_id)
    high_or_crit = [f for f in findings if f.severity in {"high", "crit"}]

    if as_json:
        click.echo(json.dumps({
            "scan_id": scan_id,
            "finding_count": len(findings),
            "high_or_crit_count": len(high_or_crit),
            "db": str(db_path),
        }))
    else:
        click.echo(
            f"Sniff scan {scan_id} done. {len(findings)} findings, "
            f"{len(high_or_crit)} high/crit."
        )

    sys.exit(1 if high_or_crit else 0)
