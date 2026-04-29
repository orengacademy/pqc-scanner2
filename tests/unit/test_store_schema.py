from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pqcscan.store.schema import Base, FindingRow, Scan


def test_create_all_yields_six_tables(tmp_db_path):
    engine = create_engine(f"sqlite:///{tmp_db_path}")
    Base.metadata.create_all(engine)
    table_names = set(Base.metadata.tables.keys())
    expected = {
        "scans", "components", "findings",
        "graph_edges", "framework_views", "baselines",
    }
    assert table_names == expected


def test_scan_round_trip(tmp_db_path):
    engine = create_engine(f"sqlite:///{tmp_db_path}")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        scan = Scan(
            started_at=datetime.utcnow(),
            host_fingerprint="abc123",
            mode="user",
            status="running",
            probe_versions={"host.openssl.config": "0.1"},
            tool_versions={},
        )
        s.add(scan)
        s.commit()
        assert scan.id is not None


def test_finding_fk_to_scan(tmp_db_path):
    engine = create_engine(f"sqlite:///{tmp_db_path}")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        scan = Scan(
            started_at=datetime.utcnow(),
            mode="user",
            status="running",
            probe_versions={},
            tool_versions={},
        )
        s.add(scan)
        s.commit()
        f = FindingRow(
            scan_id=scan.id,
            probe_id="host.openssl.config",
            algorithm="RSA-2048",
            classification="tinggi",
            severity="high",
            title="weak default cipher",
            evidence={"line": 42},
            remediation={},
        )
        s.add(f)
        s.commit()
        assert f.id is not None
        assert f.scan_id == scan.id
