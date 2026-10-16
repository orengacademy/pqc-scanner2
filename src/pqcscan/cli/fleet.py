"""`pqcscan merge` and `pqcscan diff` — fleet rollup and scan-vs-scan parity."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pqcscan.cli._db import db_arg
from pqcscan.store.repo import Repo, is_fleet_ref


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
@click.option("--db", type=str, default=None, help="SQLite file path or SQLAlchemy URL (postgresql://…).")
@click.option("--json", "as_json", is_flag=True)
@click.option("--fail-on-drift", is_flag=True,
              help="Exit 1 when the scans differ (HA/DR parity gate).")
def diff_cmd(scan_id: int, baseline_id: int, db: str | None, as_json: bool,
             fail_on_drift: bool) -> None:
    """Diff two scans by (probe, algorithm, title): added / removed / common.

    HA/DR parity: scan the primary and each peer (same DB, or merge them),
    then `pqcscan diff --scan <peer> --baseline-scan <primary> --fail-on-drift`.
    """
    repo = Repo(db_arg(db))
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


def _open_repo(db: str | None) -> Repo:
    repo = Repo(db_arg(db))
    repo.init_schema()
    return repo


def resolve_scan_ref(repo: Repo, ref: str) -> tuple[int, bool]:
    """'fleet' -> a temporary rollup scan (caller must delete_scan when done); else int id."""
    if is_fleet_ref(ref):
        rid = repo.materialize_fleet_rollup()
        if rid is None:
            raise click.ClickException("no enrolled hosts with a completed scan")
        return rid, True
    try:
        return int(ref), False
    except ValueError as e:
        raise click.BadParameter("must be a scan id or 'fleet'") from e


@click.group("agents")
def agents_cmd() -> None:
    """Enrolled fleet agents."""


@agents_cmd.command("list")
@click.option("--db", type=str, default=None, help="SQLite file path or SQLAlchemy URL (postgresql://…).")
@click.option("--json", "as_json", is_flag=True)
def agents_list(db: str | None, as_json: bool) -> None:
    repo = _open_repo(db)
    rows = [{"host_id": h.id, "hostname": h.hostname, "machine_id": h.machine_id, "os": h.os,
             "labels": h.labels or {}, "agent_version": h.agent_version, "revoked": bool(h.revoked),
             "first_seen": h.first_seen.isoformat() if h.first_seen else None,
             "last_seen": h.last_seen.isoformat() if h.last_seen else None} for h in repo.list_hosts()]
    if as_json:
        click.echo(json.dumps(rows))
        return
    for r in rows:
        flag = " (revoked)" if r["revoked"] else ""
        click.echo(f"{r['host_id']}\t{r['hostname']}\t{r['os']}\t{r['first_seen']}\t{r['last_seen']}\t{r['labels']}{flag}")


@agents_cmd.command("revoke")
@click.argument("host_id", type=int)
@click.option("--db", type=str, default=None, help="SQLite file path or SQLAlchemy URL (postgresql://…).")
def agents_revoke(host_id: int, db: str | None) -> None:
    repo = _open_repo(db)
    if not repo.revoke_host(host_id):
        click.echo(f"host {host_id} not found", err=True)
        sys.exit(3)
    click.echo(f"revoked host {host_id}; its agent must re-enroll")


@agents_cmd.command("unrevoke")
@click.argument("host_id", type=int)
@click.option("--db", type=str, default=None, help="SQLite file path or SQLAlchemy URL (postgresql://…).")
def agents_unrevoke(host_id: int, db: str | None) -> None:
    """Allow a revoked host to enroll again."""
    repo = _open_repo(db)
    if not repo.unrevoke_host(host_id):
        click.echo(f"host {host_id} not found", err=True)
        sys.exit(3)
    click.echo(f"unrevoked host {host_id}; its agent must re-enroll")


@click.group("fleet")
def fleet_cmd() -> None:
    """Fleet-wide views and maintenance."""


@fleet_cmd.command("summary")
@click.option("--db", type=str, default=None, help="SQLite file path or SQLAlchemy URL (postgresql://…).")
@click.option("--json", "as_json", is_flag=True)
def fleet_summary(db: str | None, as_json: bool) -> None:
    repo = _open_repo(db)
    rows = [{"host_id": x.host.id, "hostname": x.host.hostname, "labels": x.host.labels or {},
             "scan_id": x.scan_id, "finished_at": x.finished_at.isoformat() if x.finished_at else None,
             "readiness": x.readiness, "crit": x.crit, "high": x.high, "total": x.total}
            for x in repo.fleet_summary()]
    if as_json:
        click.echo(json.dumps(rows))
        return
    click.echo(f"{'host':24s} {'readiness':>9} {'crit':>5} {'high':>5} {'total':>6}  last scan")
    for r in rows:
        click.echo(f"{r['hostname']:24s} {r['readiness']!s:>9} {r['crit']:>5} {r['high']:>5} "
                   f"{r['total']:>6}  {r['finished_at'] or '-'}")


@fleet_cmd.command("prune")
@click.option("--keep", type=click.IntRange(min=1), default=12, show_default=True,
              help="Scans to keep per host.")
@click.option("--db", type=str, default=None, help="SQLite file path or SQLAlchemy URL (postgresql://…).")
def fleet_prune(keep: int, db: str | None) -> None:
    repo = _open_repo(db)
    n = repo.prune_scans(keep_per_host=keep)
    click.echo(f"pruned {n} scans (kept {keep} per host)")
