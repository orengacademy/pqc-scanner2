"""`pqcscan merge` and `pqcscan diff` — fleet rollup and scan-vs-scan parity."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.argument("sources", nargs=-1, type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("-o", "--out", type=click.Path(path_type=Path), required=True,
              help="Fleet DB to write (created if missing, appended otherwise).")
@click.option("--no-rollup", is_flag=True, help="Copy scans only; skip the fleet-rollup scan.")
@click.option("--json", "as_json", is_flag=True)
def merge_cmd(sources: tuple[Path, ...], out: Path, no_rollup: bool, as_json: bool) -> None:
    """Merge per-host scan DBs into one fleet DB (+ a rollup scan for fleet exports).

    Run `pqcscan scan --db host.db` on every host, collect the files, then:
    `pqcscan merge -o fleet.db hostA.db hostB.db ...`. Export the fleet with
    `pqcscan export --db fleet.db --scan <rollup id> --format cbom|xlsx-bukukerja|...`.
    """
    if not sources:
        click.echo("merge: give at least one source DB", err=True)
        sys.exit(2)
    from pqcscan.store.merge import merge_dbs
    out.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo(out)
    repo.init_schema()
    rep = merge_dbs(repo, list(sources), rollup=not no_rollup)
    if as_json:
        click.echo(json.dumps({
            "db": str(out), "sources": rep.sources, "scans_copied": rep.scans_copied,
            "findings_copied": rep.findings_copied, "rollup_scan_id": rep.rollup_scan_id,
            "rollup_hosts": rep.rollup_hosts,
        }))
        return
    click.echo(f"merged {rep.sources} DBs: {rep.scans_copied} scans, "
               f"{rep.findings_copied} findings -> {out}")
    if rep.rollup_scan_id is not None:
        click.echo(f"fleet rollup: scan {rep.rollup_scan_id} "
                   f"({len(rep.rollup_hosts)} hosts: {', '.join(rep.rollup_hosts)})")


@click.command()
@click.option("--scan", "scan_id", type=int, required=True, help="Current scan id.")
@click.option("--baseline-scan", "baseline_id", type=int, required=True,
              help="Scan to compare against (primary / baseline / HA peer).")
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--fail-on-drift", is_flag=True,
              help="Exit 1 when the scans differ (HA/DR parity gate).")
def diff_cmd(scan_id: int, baseline_id: int, db: Path | None, as_json: bool,
             fail_on_drift: bool) -> None:
    """Diff two scans by (probe, algorithm, title): added / removed / common.

    HA/DR parity: scan the primary and each peer (same DB, or merge them),
    then `pqcscan diff --scan <peer> --baseline-scan <primary> --fail-on-drift`.
    """
    repo = Repo(db or default_db_path())
    repo.init_schema()
    for sid in (scan_id, baseline_id):
        if repo.get_scan(sid) is None:
            click.echo(f"scan {sid} not found", err=True)
            sys.exit(3)
    d = repo.diff_findings(current_scan_id=scan_id, baseline_scan_id=baseline_id)
    drift = bool(d["added"] or d["removed"])

    def _row(f) -> dict:
        return {"probe_id": f.probe_id, "algorithm": f.algorithm,
                "classification": f.classification, "severity": f.severity, "title": f.title}

    if as_json:
        click.echo(json.dumps({"scan": scan_id, "baseline_scan": baseline_id,
                               "added": [_row(f) for f in d["added"]],
                               "removed": [_row(f) for f in d["removed"]],
                               "common": d["common"], "drift": drift}))
    else:
        click.echo(f"scan {scan_id} vs baseline {baseline_id}: "
                   f"+{len(d['added'])} added, -{len(d['removed'])} removed, {d['common']} common")
        for f in d["added"]:
            click.echo(f"  + [{f.severity}] {f.probe_id} {f.algorithm}: {f.title}")
        for f in d["removed"]:
            click.echo(f"  - [{f.severity}] {f.probe_id} {f.algorithm}: {f.title}")
    if fail_on_drift and drift:
        sys.exit(1)
