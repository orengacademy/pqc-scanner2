from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from pqcscan.core.types import Finding
from pqcscan.store import migrations
from pqcscan.store.schema import FindingRow, Scan


class Repo:
    def __init__(self, db_path: Path | str):
        self.engine = create_engine(f"sqlite:///{db_path}", future=True)

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
