from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

import click

from pqcscan.core.mosca import MoscaInputs, assess, summary_lines
from pqcscan.core.types import Severity
from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.runner.targets import parse_scan_inputs
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path

# --fail-on threshold names, ordered least → most severe. "none" disables the
# CI gate entirely (the scan always exits 0 unless an internal error occurs).
FAIL_ON_CHOICES = ("none", "low", "med", "high", "crit")


class _HasSeverity(Protocol):
    severity: str


def _threshold_numeric(threshold: str) -> int | None:
    """Numeric rank of a --fail-on threshold, or None for the disabled gate."""
    if threshold == "none":
        return None
    return Severity(threshold).numeric


def _findings_at_or_over(
    findings: Iterable[_HasSeverity], threshold: str,
) -> list[_HasSeverity]:
    """Findings whose severity is at or above the threshold.

    Empty when the gate is disabled (``threshold == "none"``). Severity is
    stored as a plain string on the DB row, so it is normalised through the
    ``Severity`` enum to compare on its numeric rank.
    """
    rank = _threshold_numeric(threshold)
    if rank is None:
        return []
    return [f for f in findings if Severity(str(f.severity)).numeric >= rank]


def _gate_tripped(findings: Iterable[_HasSeverity], threshold: str) -> bool:
    """True when at least one finding meets or exceeds the fail-on threshold."""
    return bool(_findings_at_or_over(findings, threshold))


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
@click.option(
    "--fail-on", "fail_on",
    type=click.Choice(FAIL_ON_CHOICES, case_sensitive=False),
    default="high", show_default=True,
    help="CI gate: exit 1 if any finding is at/above this severity. "
         "'none' disables the gate (always exit 0 unless an error).",
)
def scan_cmd(
    db: Path | None, as_json: bool, watch: bool,
    target: str | None, paths: tuple[str, ...], ot: tuple[str, ...],
    data_lifetime: float, migration_years: float, threat_years: float,
    fail_on: str,
) -> None:
    """Run a scan in-process; persist to SQLite.

    With no --target/--path/--ot the scan covers the local host only.
    Supplying targets activates the network, filesystem, and OT probe
    families against those endpoints.

    The --data-lifetime / --migration-years / --threat-years options feed
    Mosca's inequality (X+Y>Z): if the data outlives the migration+threat
    window the harvested-now data is exposed before migration completes.

    Exit codes: 0 = clean (no finding at/above --fail-on), 1 = gate tripped,
    3 = internal error. Use --fail-on to tune the CI threshold; the default
    ('high') fails the build on any high or critical finding.
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
    fail_on = fail_on.lower()
    high_or_crit = [f for f in findings if f.severity in {"high", "crit"}]
    over_threshold = _findings_at_or_over(findings, fail_on)
    gate_tripped = bool(over_threshold)

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
            "fail_on": fail_on,
            "over_threshold_count": len(over_threshold),
            "gate_tripped": gate_tripped,
            "db": str(db_path),
            "mosca": mosca.as_dict(),
        }))
    else:
        click.echo(
            f"Scan {scan_id} done. {len(findings)} findings, "
            f"{len(high_or_crit)} high/crit."
        )
        if fail_on == "none":
            click.echo("Gate: --fail-on none (disabled) → exit 0.")
        else:
            click.echo(
                f"Gate: --fail-on {fail_on} → {len(over_threshold)} finding(s) "
                f"at/above {fail_on}; "
                f"{'FAIL (exit 1)' if gate_tripped else 'pass (exit 0)'}."
            )
        click.echo(
            f"Mosca X+Y>Z: X={mosca.x:g} Y={mosca.y:g} Z={mosca.z:g} "
            f"→ verdict={mosca.verdict} (shelf-life gap {mosca.gap_years:g}y)."
        )
        click.echo(summary_lines(mosca, vulnerable_count=len(high_or_crit))["en"])

    sys.exit(1 if gate_tripped else 0)


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
