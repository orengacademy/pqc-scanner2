from __future__ import annotations

import contextlib
import os
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import create_engine, delete, event, select
from sqlalchemy.orm import Session

from pqcscan.core.types import Finding
from pqcscan.store import migrations
from pqcscan.store.schema import (
    Baseline,
    ComponentRow,
    FindingRow,
    FrameworkView,
    GraphEdge,
    Host,
    Scan,
)
from pqcscan.util.clock import utcnow

if TYPE_CHECKING:  # bundle.py imports Repo; importing it eagerly here would be a cycle
    from pqcscan.store.bundle import HostIdentity, ScanBundle


def _parse_dt(v: object) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None


_INGEST_STATUSES = frozenset({"done", "failed", "interrupted"})
FLEET_ROLLUP_LABEL = "fleet-rollup"


def is_fleet_ref(ref: str) -> bool:
    """True when a scan reference means 'the whole fleet' (case/whitespace tolerant)."""
    return ref.strip().lower() == "fleet"


@dataclass(slots=True)
class IngestResult:
    scan_id: int
    stored_findings: int
    stored_views: int
    duplicate: bool


@dataclass(slots=True)
class HostSummary:
    host: Host
    scan_id: int | None
    finished_at: datetime | None
    readiness: int | None
    crit: int
    high: int
    total: int


class Repo:
    def __init__(self, db_path: Path | str):
        # check_same_thread=False so a background-thread scanner can write
        # while the FastAPI request loop reads. SQLite handles concurrent
        # access via its built-in locking.
        # A "://" argument is a full SQLAlchemy URL (e.g. postgresql://…, fleet
        # scale); anything else is a SQLite file path.
        url = str(db_path)
        if "://" not in url:
            url = f"sqlite:///{db_path}"
        kwargs: dict = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        self.engine = create_engine(url, **kwargs)

        if self.engine.dialect.name == "sqlite":
            # WAL lets the daemon's background-thread writer coexist with request
            # readers; busy_timeout turns writer contention into a short wait
            # instead of an immediate "database is locked" error.
            @event.listens_for(self.engine, "connect")
            def _set_sqlite_pragmas(dbapi_conn, _record) -> None:
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.close()
                # The DB holds the host's full crypto inventory (key paths, weak
                # configs): owner-only, whatever the umask. SQLite gives -wal/-shm
                # the main file's mode, so one chmod covers all three.
                with contextlib.suppress(OSError):
                    if os.path.isfile(str(db_path)):
                        os.chmod(str(db_path), 0o600)

    def init_schema(self) -> None:
        migrations.apply(self.engine)

    def create_scan(
        self,
        *,
        mode: str,
        probe_versions: dict[str, str],
        tool_versions: dict[str, str],
        host_fingerprint: str | None = None,
        scan_uuid: str | None = None,
    ) -> int:
        with Session(self.engine) as s:
            scan = Scan(
                started_at=utcnow(),
                host_fingerprint=host_fingerprint,
                scan_uuid=scan_uuid or str(uuid.uuid4()),
                mode=mode,
                status="running",
                probe_versions=probe_versions,
                tool_versions=tool_versions,
            )
            s.add(scan)
            s.commit()
            return scan.id

    def has_running_scan(self) -> bool:
        with Session(self.engine) as s:
            stmt = select(Scan.id).where(Scan.status == "running").limit(1)
            return s.execute(stmt).first() is not None

    def begin_scan_if_idle(
        self,
        *,
        mode: str,
        probe_versions: dict[str, str],
        tool_versions: dict[str, str],
        host_fingerprint: str | None = None,
        scan_uuid: str | None = None,
    ) -> int | None:
        """Check-no-running-scan and insert the new 'running' row in ONE
        transaction, returning its id — or None if a scan is already running.
        Closing the check then start race the two-step has_running_scan +
        create_scan left open."""
        with Session(self.engine) as s:
            running = s.execute(
                select(Scan.id).where(Scan.status == "running").limit(1)
            ).first()
            if running is not None:
                return None
            scan = Scan(
                started_at=utcnow(),
                host_fingerprint=host_fingerprint,
                scan_uuid=scan_uuid or str(uuid.uuid4()),
                mode=mode,
                status="running",
                probe_versions=probe_versions,
                tool_versions=tool_versions,
            )
            s.add(scan)
            s.commit()
            return scan.id

    def reconcile_running_scans(self) -> int:
        """Mark scans still 'running' as 'interrupted'. Call on daemon startup:
        a crash/restart leaves the in-flight scan's row stuck at 'running'
        (daemon scan threads are daemonic and die with the process), which
        otherwise wedges the one-scan-at-a-time guard forever. Returns the
        number of rows swept."""
        with Session(self.engine) as s:
            stale = list(
                s.execute(select(Scan).where(Scan.status == "running")).scalars()
            )
            for scan in stale:
                scan.status = "interrupted"
                if scan.finished_at is None:
                    scan.finished_at = utcnow()
            s.commit()
            n = len(stale)
        self.delete_stale_rollups()
        return n

    def finish_scan(self, scan_id: int, *, status: str) -> None:
        with Session(self.engine) as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise ValueError(f"scan {scan_id} not found")
            scan.status = status
            scan.finished_at = utcnow()
            s.commit()

    def record_finding(self, scan_id: int, f: Finding) -> int:
        with Session(self.engine) as s:
            row = FindingRow(
                scan_id=scan_id,
                probe_id=f.probe_id,
                algorithm=f.algorithm,
                classification=f.classification.value,
                severity=f.severity.value,
                title=f.title,
                evidence=f.evidence,
                remediation=f.remediation,
                created_at=f.created_at,
            )
            s.add(row)
            s.commit()
            return row.id

    def record_probe_error(self, scan_id: int, *, probe_id: str, message: str) -> int:
        with Session(self.engine) as s:
            row = FindingRow(
                scan_id=scan_id,
                probe_id=probe_id,
                algorithm="N/A",
                classification="error",
                severity="info",
                title=f"probe error: {message}",
                evidence={"error": message},
                remediation={},
            )
            s.add(row)
            s.commit()
            return row.id

    def list_scans(self) -> list[Scan]:
        with Session(self.engine) as s:
            return list(
                s.execute(select(Scan).order_by(Scan.started_at.desc())).scalars()
            )

    def list_findings(self, scan_id: int) -> list[FindingRow]:
        with Session(self.engine) as s:
            return list(
                s.execute(
                    select(FindingRow)
                    .where(FindingRow.scan_id == scan_id)
                    .order_by(FindingRow.created_at)
                ).scalars()
            )

    def get_scan(self, scan_id: int) -> Scan | None:
        with Session(self.engine) as s:
            return s.get(Scan, scan_id)

    def list_findings_bulk(self, scan_ids: list[int]) -> dict[int, list[FindingRow]]:
        """All findings for several scans in ONE query, grouped by scan id.

        Replaces the dashboard's per-scan N+1 loop (one Session per trend
        point). Every requested id is present in the result, even with no
        findings."""
        grouped: dict[int, list[FindingRow]] = {sid: [] for sid in scan_ids}
        if not scan_ids:
            return grouped
        with Session(self.engine) as s:
            rows = s.execute(
                select(FindingRow)
                .where(FindingRow.scan_id.in_(scan_ids))
                .order_by(FindingRow.created_at)
            ).scalars()
            for r in rows:
                grouped[r.scan_id].append(r)
        return grouped

    def record_framework_view(
        self,
        finding_id: int,
        *,
        framework: str,
        clause: str,
        verdict: str,
        deadline: date | None = None,
    ) -> int:
        with Session(self.engine) as s:
            row = FrameworkView(
                finding_id=finding_id,
                framework=framework,
                clause=clause,
                verdict=verdict,
                deadline=deadline,
            )
            s.add(row)
            s.commit()
            return row.id

    def list_framework_views(
        self, scan_id: int, *, framework: str | None = None
    ) -> list[FrameworkView]:
        with Session(self.engine) as s:
            stmt = (
                select(FrameworkView)
                .join(FindingRow, FrameworkView.finding_id == FindingRow.id)
                .where(FindingRow.scan_id == scan_id)
            )
            if framework is not None:
                stmt = stmt.where(FrameworkView.framework == framework)
            return list(s.execute(stmt).scalars())

    def create_baseline(
        self, *, scan_id: int, label: str, notes: str | None = None
    ) -> int:
        with Session(self.engine) as s:
            if s.get(Scan, scan_id) is None:
                raise ValueError(f"scan {scan_id} not found")
            row = Baseline(scan_id=scan_id, label=label, notes=notes)
            s.add(row)
            s.commit()
            return row.id

    def list_baselines(self) -> list[Baseline]:
        with Session(self.engine) as s:
            return list(
                s.execute(
                    select(Baseline).order_by(Baseline.created_at.desc())
                ).scalars()
            )

    def get_baseline(self, baseline_id: int) -> Baseline | None:
        with Session(self.engine) as s:
            return s.get(Baseline, baseline_id)

    def diff_findings(
        self, *, current_scan_id: int, baseline_scan_id: int
    ) -> dict:
        """Set-diff of findings between two scans by (probe_id, algorithm, title).

        Evidence dicts often carry timestamps and absolute paths that drift
        across scans, so identity uses the stable triple. Returns:
          {"added":   [FindingRow, ...]  # in current, not in baseline
           "removed": [FindingRow, ...]  # in baseline, not in current
           "common":  int}               # count of unchanged findings
        """
        current = self.list_findings(current_scan_id)
        baseline = self.list_findings(baseline_scan_id)

        def key(f: FindingRow) -> tuple[str, str, str]:
            return (f.probe_id, f.algorithm, f.title)

        baseline_keys = {key(f) for f in baseline}
        current_keys = {key(f) for f in current}
        added = [f for f in current if key(f) not in baseline_keys]
        removed = [f for f in baseline if key(f) not in current_keys]
        common = len(current_keys & baseline_keys)
        return {"added": added, "removed": removed, "common": common}

    # ------------------------------------------------------------------ fleet
    def upsert_host(self, identity: HostIdentity, *, token_hash: str | None = None) -> Host:
        with Session(self.engine) as s:
            h = s.execute(select(Host).where(Host.machine_id == identity.machine_id)).scalar_one_or_none()
            if h is None:
                h = Host(machine_id=identity.machine_id)
                s.add(h)
            h.hostname = identity.hostname or h.hostname
            h.os = identity.os or h.os
            h.labels = {**(h.labels or {}), **identity.labels}
            h.agent_version = identity.agent_version or h.agent_version
            h.last_seen = utcnow()
            if token_hash is not None:
                h.token_hash = token_hash   # never clears `revoked`: only unrevoke_host does
            s.commit()
            s.refresh(h)
            s.expunge(h)
            return h

    def get_host(self, host_id: int) -> Host | None:
        with Session(self.engine) as s:
            return s.get(Host, host_id)

    def get_host_by_machine_id(self, machine_id: str) -> Host | None:
        with Session(self.engine) as s:
            return s.execute(select(Host).where(Host.machine_id == machine_id)).scalar_one_or_none()

    def get_host_by_token_hash(self, token_hash: str) -> Host | None:
        with Session(self.engine) as s:
            return s.execute(select(Host).where(Host.token_hash == token_hash)).scalar_one_or_none()

    def list_hosts(self) -> list[Host]:
        with Session(self.engine) as s:
            return list(s.execute(select(Host).order_by(Host.hostname, Host.id)).scalars())

    def revoke_host(self, host_id: int) -> bool:
        with Session(self.engine) as s:
            h = s.get(Host, host_id)
            if h is None:
                return False
            h.revoked = True
            h.token_hash = None
            s.commit()
            return True

    def get_scan_id_by_uuid(self, scan_uuid: str) -> int | None:
        with Session(self.engine) as s:
            return s.execute(select(Scan.id).where(Scan.scan_uuid == scan_uuid)).scalar_one_or_none()

    def unrevoke_host(self, host_id: int) -> bool:
        """Re-approve a revoked host. The token stays cleared, so the agent must re-enroll."""
        with Session(self.engine) as s:
            h = s.get(Host, host_id)
            if h is None:
                return False
            h.revoked = False
            s.commit()
            return True

    def ingest_bundle(self, bundle: ScanBundle, host_id: int) -> IngestResult:
        """Store one bundle in a single transaction; a repeated scan_uuid is a no-op."""
        with Session(self.engine) as s:
            if s.get(Host, host_id) is None:
                raise ValueError(f"host {host_id} not found")
            existing = s.execute(
                select(Scan.id, Scan.host_id).where(Scan.scan_uuid == bundle.scan_uuid)
            ).one_or_none()
            if existing is not None:
                if existing.host_id != host_id:
                    raise ValueError("scan_uuid belongs to another host")
                return IngestResult(scan_id=existing.id, stored_findings=0, stored_views=0, duplicate=True)
            sc = bundle.scan
            status = str(sc.get("status", "done"))
            scan = Scan(
                started_at=_parse_dt(sc.get("started_at")) or utcnow(),
                finished_at=_parse_dt(sc.get("finished_at")),
                host_fingerprint=bundle.host.hostname, mode=str(sc.get("mode", "user")),
                status=status if status in _INGEST_STATUSES else "done", label=None,
                probe_versions=dict(sc.get("probe_versions") or {}),
                tool_versions=dict(sc.get("tool_versions") or {}),
                host_id=host_id, scan_uuid=bundle.scan_uuid,
            )
            s.add(scan)
            s.flush()
            n_f = n_v = 0
            for f in bundle.findings:
                row = FindingRow(
                    scan_id=scan.id, probe_id=str(f["probe_id"]), algorithm=str(f.get("algorithm", "N/A")),
                    classification=str(f.get("classification", "info")), severity=str(f.get("severity", "info")),
                    title=str(f.get("title", "")), evidence=dict(f.get("evidence") or {}),
                    remediation=dict(f.get("remediation") or {}),
                    created_at=_parse_dt(f.get("created_at")) or utcnow(),
                )
                s.add(row)
                s.flush()
                n_f += 1
                for v in f.get("views") or []:
                    s.add(FrameworkView(finding_id=row.id, framework=str(v["framework"]), clause=str(v["clause"]),
                                        verdict=str(v["verdict"]),
                                        deadline=date.fromisoformat(v["deadline"]) if v.get("deadline") else None))
                    n_v += 1
            h = s.get(Host, host_id)
            if h is not None:
                h.last_seen = utcnow()
            s.commit()
            return IngestResult(scan_id=scan.id, stored_findings=n_f, stored_views=n_v, duplicate=False)

    def fleet_summary(self) -> list[HostSummary]:
        from pqcscan.core.bands import count_bands, readiness_score
        out: list[HostSummary] = []
        with Session(self.engine) as s:
            for h in s.execute(select(Host).order_by(Host.hostname, Host.id)).scalars().all():
                latest = s.execute(
                    select(Scan).where(Scan.host_id == h.id, Scan.status == "done")
                    .order_by(Scan.id.desc()).limit(1)
                ).scalar_one_or_none()
                s.expunge(h)
                if latest is None:
                    out.append(HostSummary(h, None, None, None, 0, 0, 0))
                    continue
                rows = s.execute(select(FindingRow).where(FindingRow.scan_id == latest.id)).scalars().all()
                counts = count_bands(list(rows))
                # A host with nothing rated is fully ready, not 0 (readiness_score is 0 on an empty denominator).
                rated = counts["green"] + counts["yellow"] + counts["red"]
                out.append(HostSummary(
                    host=h, scan_id=latest.id, finished_at=latest.finished_at,
                    readiness=readiness_score(counts) if rated else 100,
                    crit=sum(1 for r in rows if r.severity == "crit"),
                    high=sum(1 for r in rows if r.severity == "high"), total=len(rows),
                ))
        return out

    def host_history(self, host_id: int, limit: int = 50) -> list[Scan]:
        with Session(self.engine) as s:
            return list(s.execute(select(Scan).where(Scan.host_id == host_id)
                                  .order_by(Scan.id.desc()).limit(limit)).scalars())

    def delete_scan(self, scan_id: int) -> None:
        with Session(self.engine) as s:
            fids = select(FindingRow.id).where(FindingRow.scan_id == scan_id)
            s.execute(delete(FrameworkView).where(FrameworkView.finding_id.in_(fids)))
            s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
            s.execute(delete(Baseline).where(Baseline.scan_id == scan_id))
            s.execute(delete(GraphEdge).where(GraphEdge.scan_id == scan_id))
            s.execute(delete(ComponentRow).where(ComponentRow.scan_id == scan_id))
            s.execute(delete(Scan).where(Scan.id == scan_id))
            s.commit()

    def prune_scans(self, keep_per_host: int) -> int:
        """Delete each host's scans beyond the newest N (by server scan id); returns scans deleted."""
        if keep_per_host < 1:
            raise ValueError("keep_per_host must be >= 1")
        self.delete_stale_rollups()
        deleted = 0
        with Session(self.engine) as s:
            host_ids = list(s.execute(select(Host.id)).scalars())
        for hid in host_ids:
            with Session(self.engine) as s:
                old = list(s.execute(select(Scan.id).where(Scan.host_id == hid)
                                     .order_by(Scan.id.desc()).offset(keep_per_host)).scalars())
            for sid in old:
                self.delete_scan(sid)
                deleted += 1
        return deleted

    def delete_stale_rollups(self) -> int:
        """Delete orphaned temporary fleet rollups (left by a hard kill mid-export); returns count.

        Only rollups flagged temporary are swept: `pqcscan merge` also labels its persistent
        rollup scan FLEET_ROLLUP_LABEL, and that one is user data."""
        with Session(self.engine) as s:
            ids = [i for i, tv in s.execute(select(Scan.id, Scan.tool_versions)
                                            .where(Scan.label == FLEET_ROLLUP_LABEL))
                   if (tv or {}).get("temporary") is True]
        for sid in ids:
            self.delete_scan(sid)
        return len(ids)

    def materialize_fleet_rollup(self) -> int | None:
        """Temporary scan = latest done scan of every host, evidence['host'] set. Caller deletes it."""
        summary = [x for x in self.fleet_summary() if x.scan_id is not None]
        if not summary:
            return None
        with Session(self.engine) as s:
            roll = Scan(started_at=utcnow(), finished_at=utcnow(), host_fingerprint="fleet", mode="user",
                        status="done", label=FLEET_ROLLUP_LABEL, probe_versions={},
                        tool_versions={"hosts": len(summary), "temporary": True}, scan_uuid=str(uuid.uuid4()))
            s.add(roll)
            s.flush()
            for x in summary:
                for r in s.execute(select(FindingRow).where(FindingRow.scan_id == x.scan_id)).scalars().all():
                    nf = FindingRow(scan_id=roll.id, probe_id=r.probe_id, algorithm=r.algorithm,
                                    classification=r.classification, severity=r.severity, title=r.title,
                                    evidence={**(r.evidence or {}), "host": x.host.hostname},
                                    remediation=r.remediation, created_at=r.created_at)
                    s.add(nf)
                    s.flush()
                    for v in s.execute(select(FrameworkView).where(FrameworkView.finding_id == r.id)).scalars():
                        s.add(FrameworkView(finding_id=nf.id, framework=v.framework, clause=v.clause,
                                            verdict=v.verdict, deadline=v.deadline))
            s.commit()
            return roll.id
