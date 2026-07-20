from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from pqcscan.core.mosca import MoscaInputs, assess, summary_lines
from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.runner.targets import parse_scan_inputs
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON to stdout.")
@click.option("--watch", is_flag=True, help="Stream events to stderr while scanning.")
@click.option(
    "--target", default=None,
    help="Network endpoint host[:port] for TLS/STARTTLS probes "
         "(e.g. example.com or example.com:8443).",
)
@click.option(
    "--path", "paths", multiple=True,
    type=click.Path(),
    help="Filesystem path to scan for certs/keys/code (repeatable).",
)
@click.option(
    "--ot", "ot", multiple=True,
    help="OT/ICS endpoint host:port[:proto] (repeatable), "
         "e.g. plc.local:502:modbus.",
)
@click.option(
    "--data-lifetime", "data_lifetime", type=float, default=10.0, show_default=True,
    help="Mosca X: years the data must stay secret (data-lifetime).",
)
@click.option(
    "--migration-years", "migration_years", type=float, default=5.0, show_default=True,
    help="Mosca Y: years to migrate to post-quantum crypto.",
)
@click.option(
    "--threat-years", "threat_years", type=float, default=10.0, show_default=True,
    help="Mosca Z: years until a cryptographically-relevant quantum computer.",
)
def scan_cmd(
    db: Path | None, as_json: bool, watch: bool,
    target: str | None, paths: tuple[str, ...], ot: tuple[str, ...],
    data_lifetime: float, migration_years: float, threat_years: float,
) -> None:
    """Run a scan in-process; persist to SQLite.

    With no --target/--path/--ot the scan covers the local host only.
    Supplying targets activates the network, filesystem, and OT probe
    families against those endpoints.

    The --data-lifetime / --migration-years / --threat-years options feed
    Mosca's inequality (X+Y>Z): if the data outlives the migration+threat
    window the harvested-now data is exposed before migration completes.
    """
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo(db_path)
    repo.init_schema()
    bus = EventBus()
    registry = default_registry()
    runner = ProbeRunner(registry=registry, repo=repo, bus=bus)

    scan_paths, server_target, ot_targets = parse_scan_inputs(
        target=target, paths=list(paths), ot=list(ot),
    )

    async def _go() -> int:
        watcher_task = None
        if watch:
            async def _watch() -> None:
                async for ev in bus.subscribe():
                    click.echo(f"[event] {type(ev).__name__}: {ev}", err=True)
            watcher_task = asyncio.create_task(_watch())
        scan_id = await runner.run(
            mode=current_mode(),
            available_capabilities=detect_capabilities(),
            scan_paths=scan_paths,
            server_target=server_target,
            ot_targets=ot_targets,
        )
        if watcher_task:
            watcher_task.cancel()
        return scan_id

    scan_id = asyncio.run(_go())
    findings = repo.list_findings(scan_id)
    high_or_crit = [f for f in findings if f.severity in {"high", "crit"}]

    mosca_inputs = MoscaInputs(
        data_lifetime_years=data_lifetime,
        migration_years=migration_years,
        threat_years=threat_years,
    )
    mosca = assess(mosca_inputs)

    if as_json:
        click.echo(json.dumps({
            "scan_id": scan_id,
            "finding_count": len(findings),
            "high_or_crit_count": len(high_or_crit),
            "db": str(db_path),
            "mosca": mosca.as_dict(),
        }))
    else:
        click.echo(
            f"Scan {scan_id} done. {len(findings)} findings, "
            f"{len(high_or_crit)} high/crit."
        )
        click.echo(
            f"Mosca X+Y>Z: X={mosca.x:g} Y={mosca.y:g} Z={mosca.z:g} "
            f"→ verdict={mosca.verdict} (shelf-life gap {mosca.gap_years:g}y)."
        )
        click.echo(summary_lines(mosca, vulnerable_count=len(high_or_crit))["en"])

    sys.exit(1 if high_or_crit else 0)


@click.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
def scans_cmd(db: Path | None) -> None:
    """List scans."""
    repo = Repo(db or default_db_path())
    repo.init_schema()
    for s in repo.list_scans():
        click.echo(f"{s.id}\t{s.started_at.isoformat()}\t{s.status}\t{s.mode}")


@click.command()
@click.option("--id", "scan_id", type=int, required=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def status_cmd(scan_id: int, db: Path | None) -> None:
    """Show one scan's status."""
    repo = Repo(db or default_db_path())
    repo.init_schema()
    s = repo.get_scan(scan_id)
    if s is None:
        click.echo(f"scan {scan_id} not found", err=True)
        sys.exit(3)
    click.echo(
        f"id={s.id} status={s.status} mode={s.mode} "
        f"started={s.started_at.isoformat()}"
    )
