"""Fleet merge: fold many per-host scan DBs into one, plus a rollup scan.

`pqcscan scan` is one host (or one target) → one SQLite DB. For an estate you
run the binary on every host, collect the DBs, and merge them here. Every
source scan is copied verbatim (new ids, original timestamps, host fingerprint
kept or taken from the file name) so per-host drill-down and `pqcscan diff`
still work; a synthetic **rollup** scan unions the latest completed scan of
each source with `evidence["host"]` set, so every existing export (CBOM,
SARIF, BUKUKERJA, PDF, readiness score) runs unchanged against the whole
fleet by pointing it at the rollup scan id.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from pqcscan.store.repo import FLEET_ROLLUP_LABEL, Repo
from pqcscan.store.schema import FindingRow, FrameworkView, Scan
from pqcscan.util.clock import utcnow

ROLLUP_LABEL = FLEET_ROLLUP_LABEL


@dataclass(slots=True)
class MergeReport:
    sources: int = 0
    scans_copied: int = 0
    findings_copied: int = 0
    rollup_scan_id: int | None = None
    rollup_hosts: list[str] = field(default_factory=list)


def _copy_scan(src: Session, dst: Session, scan: Scan, *, host: str,
               label: str | None = None, extra_evidence: dict | None = None) -> tuple[int, int]:
    """Copy one scan + findings + framework views; returns (new_scan_id, n_findings)."""
    new = Scan(
        started_at=scan.started_at, finished_at=scan.finished_at,
        host_fingerprint=host, mode=scan.mode, status=scan.status,
        label=label if label is not None else scan.label,
        probe_versions=scan.probe_versions, tool_versions=scan.tool_versions,
    )
    dst.add(new)
    dst.flush()
    rows = src.execute(select(FindingRow).where(FindingRow.scan_id == scan.id)
                       .order_by(FindingRow.created_at)).scalars().all()
    n = 0
    for r in rows:
        nf = FindingRow(
            scan_id=new.id, probe_id=r.probe_id, algorithm=r.algorithm,
            classification=r.classification, severity=r.severity, title=r.title,
            evidence={**(r.evidence or {}), **(extra_evidence or {})},
            remediation=r.remediation, created_at=r.created_at,
        )
        dst.add(nf)
        dst.flush()
        for v in src.execute(select(FrameworkView).where(FrameworkView.finding_id == r.id)).scalars():
            dst.add(FrameworkView(finding_id=nf.id, framework=v.framework, clause=v.clause,
                                  verdict=v.verdict, deadline=v.deadline))
        n += 1
    return new.id, n


def merge_dbs(out: Repo, sources: list[Path], *, rollup: bool = True) -> MergeReport:
    report = MergeReport()
    latest: list[tuple[Path, str, Scan]] = []  # (source, host, latest done scan)
    with Session(out.engine) as dst:
        for path in sources:
            src_repo = Repo(path)
            src_repo.init_schema()
            report.sources += 1
            with Session(src_repo.engine) as src:
                scans = src.execute(select(Scan).order_by(Scan.started_at)).scalars().all()
                for scan in scans:
                    host = scan.host_fingerprint or path.stem
                    _, n = _copy_scan(src, dst, scan, host=host)
                    report.scans_copied += 1
                    report.findings_copied += n
                done = [s for s in scans if s.status == "done" and s.label != ROLLUP_LABEL]
                if done:
                    latest.append((path, done[-1].host_fingerprint or path.stem, done[-1]))
        if rollup and latest:
            roll = Scan(started_at=utcnow(), finished_at=utcnow(), host_fingerprint="fleet",
                        mode="user", status="done", label=ROLLUP_LABEL,
                        probe_versions={}, tool_versions={"hosts": len(latest)})
            dst.add(roll)
            dst.flush()
            for path, host, scan in latest:
                src_repo = Repo(path)
                with Session(src_repo.engine) as src:
                    rows = src.execute(select(FindingRow).where(FindingRow.scan_id == scan.id)).scalars().all()
                    for r in rows:
                        nf = FindingRow(
                            scan_id=roll.id, probe_id=r.probe_id, algorithm=r.algorithm,
                            classification=r.classification, severity=r.severity,
                            title=r.title, evidence={**(r.evidence or {}), "host": host},
                            remediation=r.remediation, created_at=r.created_at,
                        )
                        dst.add(nf)
                        dst.flush()
                        for v in src.execute(select(FrameworkView)
                                             .where(FrameworkView.finding_id == r.id)).scalars():
                            dst.add(FrameworkView(finding_id=nf.id, framework=v.framework,
                                                  clause=v.clause, verdict=v.verdict,
                                                  deadline=v.deadline))
                report.rollup_hosts.append(host)
            report.rollup_scan_id = roll.id
        dst.commit()
    return report
