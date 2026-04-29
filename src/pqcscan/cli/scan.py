from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON to stdout.")
@click.option("--watch", is_flag=True, help="Stream events to stderr while scanning.")
def scan_cmd(db: Path | None, as_json: bool, watch: bool) -> None:
    """Run a scan in-process; persist to SQLite."""
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo(db_path)
    repo.init_schema()
    bus = EventBus()
    registry = default_registry()
    runner = ProbeRunner(registry=registry, repo=repo, bus=bus)

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
        )
        if watcher_task:
            watcher_task.cancel()
        return scan_id

    scan_id = asyncio.run(_go())
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
            f"Scan {scan_id} done. {len(findings)} findings, "
            f"{len(high_or_crit)} high/crit."
        )

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
