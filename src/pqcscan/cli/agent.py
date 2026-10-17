"""`pqcscan agent` — scheduler loop around `scan --report-to` for hosts with no cron/CM agent."""
from __future__ import annotations

import random
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import click
import httpx
from loguru import logger

from pqcscan.cli._db import db_arg, ensure_db_parent
from pqcscan.cli._report import (
    PermanentRejectError,
    ReportError,
    check_server_scheme,
    default_state_dir,
    ensure_agent_token,
    flush_spool,
    make_client,
    report_scan,
)
from pqcscan.util.hostid import host_identity, parse_labels

_DUR = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_MAX_BACKOFF_S = 3600.0
_monotonic = time.monotonic          # tests replace these two to drive the loop without sleeping


def _wait(stop: threading.Event, seconds: float) -> None:
    stop.wait(seconds)               # a SIGTERM sets `stop` and wakes the sleep at once


def parse_duration(text: str) -> float:
    m = _DUR.match(text.strip())
    if not m:
        raise ValueError(f"bad duration {text!r}; use e.g. 90s, 15m, 24h, 1d")
    return float(int(m.group(1)) * _UNITS[m.group(2)])


def next_delay(base_s: float, jitter_s: float, failures: int) -> float:
    if failures > 0:
        return float(min(60.0 * (2 ** min(failures - 1, 16)), _MAX_BACKOFF_S))
    return base_s + random.uniform(0, jitter_s)


@dataclass(slots=True)
class AgentConfig:
    server: str
    enroll_token: str | None
    labels: dict[str, str]
    state_dir: Path
    paths: list[str]
    keep_local: int = 3
    db: Path | str | None = None          # default: <state_dir>/agent.db
    allow_http: bool = False


@dataclass(slots=True)
class CycleResult:
    scan_id: int
    reported: bool
    spooled: bool
    re_enrolled: bool


def owns_db(cfg: AgentConfig) -> bool:
    """True only for the agent's own default DB; --keep-local never prunes any other database."""
    return cfg.db is None or (isinstance(cfg.db, Path)
                              and cfg.db.resolve() == (cfg.state_dir / "agent.db").resolve())


def agent_cycle(cfg: AgentConfig, client: httpx.Client) -> CycleResult:
    """Scan once, then hand the bundle to report_scan (flush spool, POST, spool on failure, re-enroll on 401)."""
    from pqcscan.cli.scan import run_local_scan
    if not cfg.state_dir.exists():
        cfg.state_dir.mkdir(parents=True)
        cfg.state_dir.chmod(0o700)            # holds the agent token and spool; ensure_db_parent would make it 0755
    db = cfg.db or cfg.state_dir / "agent.db"
    repo, sid = run_local_scan(db_path=db, paths=cfg.paths)
    re_enrolled = False

    def _mark() -> None:
        nonlocal re_enrolled
        re_enrolled = True

    report: dict | None = None
    rejected = False
    try:
        report = report_scan(repo, sid, server=cfg.server, enroll_token=cfg.enroll_token, agent_token=None,
                             labels=cfg.labels, state_dir=cfg.state_dir, client=client,
                             allow_http=cfg.allow_http, on_reenroll=_mark)
    except PermanentRejectError as e:
        rejected = True                       # the server will never take this bundle: a failed cycle
        click.echo(f"agent: report rejected ({e.status}): {e.detail}", err=True)
    # The collector holds history; keep the agent's own local DB bounded.
    if owns_db(cfg):
        for old in [s.id for s in repo.list_scans()][cfg.keep_local:]:
            repo.delete_scan(old)
    return CycleResult(sid, reported=report is not None, spooled=report is None and not rejected,
                       re_enrolled=re_enrolled)


def flush_only(cfg: AgentConfig, client: httpx.Client) -> CycleResult:
    """Retry spooled bundles without scanning. reported=True means the spool drained."""
    try:
        check_server_scheme(cfg.server, cfg.allow_http)
        token = ensure_agent_token(cfg.server, enroll_token=cfg.enroll_token, identity=host_identity(cfg.labels),
                                   state_dir=cfg.state_dir, client=client)
        sent, kept, rejected = flush_spool(cfg.server, token, cfg.state_dir, client)
    except ReportError as e:
        logger.warning("agent: spool flush failed ({})", e)
        return CycleResult(0, reported=False, spooled=True, re_enrolled=False)
    if sent:
        click.echo(f"agent: sent {sent} spooled report(s)")
    if rejected:
        click.echo(f"agent: {rejected} spooled report(s) rejected; moved to spool/rejected", err=True)
    return CycleResult(0, reported=kept == 0, spooled=kept > 0, re_enrolled=False)


@click.command("agent")
@click.option("--server", required=True, help="Fleet daemon URL, e.g. https://pqc.internal:8765")
@click.option("--enroll-token", default=None, envvar="PQCSCAN_ENROLL_TOKEN")
@click.option("--labels", multiple=True, help="k=v labels (repeatable / comma-separated).")
@click.option("--interval", default="24h", show_default=True, help="Time between scans (s/m/h/d).")
@click.option("--jitter", default="2h", show_default=True, help="Random extra delay to spread load.")
@click.option("--once", is_flag=True, help="One cycle then exit (for cron).")
@click.option("--state-dir", type=click.Path(path_type=Path), default=None,
              help="Token + spool directory (default: <db dir>/agent).")
@click.option("--db", type=str, default=None,
              help="Local scan DB, SQLite path or SQLAlchemy URL (default: <state-dir>/agent.db).")
@click.option("--path", "paths", multiple=True, type=click.Path(), help="Scope file probes (repeatable).")
@click.option("--keep-local", type=click.IntRange(min=1), default=3, show_default=True,
              help="Local scans to keep in the agent DB.")
@click.option("--ca-cert", type=click.Path(path_type=Path, exists=True), default=None)
@click.option("--insecure", is_flag=True, help="Skip TLS verification (lab only).")
@click.option("--allow-http", "allow_http", is_flag=True,
              help="Allow plain http to a non-loopback host (credentials in clear text).")
def agent_cmd(server: str, enroll_token: str | None, labels: tuple[str, ...], interval: str, jitter: str,
              once: bool, state_dir: Path | None, db: str | None, paths: tuple[str, ...], keep_local: int,
              ca_cert: Path | None, insecure: bool, allow_http: bool) -> None:
    """Run scans on a schedule and push them to the fleet daemon."""
    try:
        base, jit = parse_duration(interval), parse_duration(jitter)
        check_server_scheme(server, allow_http)
    except (ValueError, ReportError) as e:
        click.echo(e.detail if isinstance(e, ReportError) else str(e), err=True)
        sys.exit(2)
    if base <= 0:
        raise click.BadParameter("--interval must be > 0")
    db_value = db_arg(db) if db else None
    if db_value is not None:
        ensure_db_parent(db_value)
    cfg = AgentConfig(server=server, enroll_token=enroll_token, labels=parse_labels(labels),
                      state_dir=state_dir or default_state_dir(db_value), paths=list(paths),
                      keep_local=keep_local, db=db_value, allow_http=allow_http)
    if not owns_db(cfg):
        click.echo("--keep-local ignored: database is not <state-dir>/agent.db", err=True)
    # A spooled report is not a failure; only a crashed or permanently rejected cycle is. After a spool, retry
    # the flush (not the scan) on backoff until it drains, but never later than the next scheduled scan,
    # which also re-enrolls.
    stop = threading.Event()
    previous = signal.signal(signal.SIGTERM, lambda *_: stop.set())
    failures = retries = 0
    next_scan = 0.0
    try:
        with make_client(ca_cert=ca_cert, insecure=insecure) as client:
            while not stop.is_set():
                if _monotonic() >= next_scan:
                    try:
                        r = agent_cycle(cfg, client)
                        if not (r.reported or r.spooled):     # permanently rejected: count as a failure
                            failures, retries = failures + 1, 0
                        else:
                            failures, retries = 0, 0 if r.reported else 1
                        if r.reported:
                            click.echo(f"agent: scan {r.scan_id} reported")
                        elif r.spooled:
                            click.echo(f"agent: scan {r.scan_id} done; report spooled; will retry next cycle",
                                       err=True)
                    except Exception as e:  # a failed scan must not kill the loop
                        failures, retries = failures + 1, 0
                        logger.exception("agent: cycle failed: {}", e)
                    next_scan = _monotonic() + next_delay(base, jit, failures)    # from cycle end, not start
                else:
                    try:
                        drained = flush_only(cfg, client).reported
                    except Exception as e:  # a bad tick must not kill the loop
                        logger.exception("agent: spool flush failed: {}", e)
                        drained = False
                    retries = 0 if drained else retries + 1
                if once:
                    sys.exit(0 if failures == 0 else 1)
                wait = next_scan - _monotonic()
                if retries:
                    wait = min(wait, next_delay(base, jit, retries))
                _wait(stop, max(wait, 0.0))
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous)
    click.echo("agent: stopping", err=True)
