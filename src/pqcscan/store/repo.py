from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from pqcscan.core.types import Finding
from pqcscan.store import migrations
from pqcscan.store.schema import Baseline, FindingRow, FrameworkView, Scan


class Repo:
    def __init__(self, db_path: Path | str):
        # check_same_thread=False so a background-thread scanner can write
        # while the FastAPI request loop reads. SQLite handles concurrent
        # access via its built-in locking.
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            future=True,
            connect_args={"check_same_thread": False},
        )

    def init_schema(self) -> None:
        migrations.apply(self.engine)

    def create_scan(
        self,
        *,
        mode: str,
        probe_versions: dict[str, str],
        tool_versions: dict[str, str],
        host_fingerprint: str | None = None,
    ) -> int:
        with Session(self.engine) as s:
            scan = Scan(
                started_at=datetime.utcnow(),
                host_fingerprint=host_fingerprint,
                mode=mode,
                status="running",
                probe_versions=probe_versions,
                tool_versions=tool_versions,
            )
            s.add(scan)
            s.commit()
            return scan.id

    def finish_scan(self, scan_id: int, *, status: str) -> None:
        with Session(self.engine) as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise ValueError(f"scan {scan_id} not found")
            scan.status = status
            scan.finished_at = datetime.utcnow()
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
