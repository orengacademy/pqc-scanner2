from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.repo import Repo


def test_init_creates_schema(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    repo.init_schema()  # idempotent


def test_create_scan_and_finish(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={"x": "1"}, tool_versions={}
    )
    assert scan_id > 0
    repo.finish_scan(scan_id, status="done")
    scans = repo.list_scans()
    assert len(scans) == 1 and scans[0].status == "done"


def test_record_finding_round_trip(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    f = Finding(
        probe_id="host.openssl.config",
        algorithm="RSA-2048",
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title="weak cipher",
        evidence={"line": 42},
    )
    repo.record_finding(scan_id, f)
    rows = repo.list_findings(scan_id)
    assert len(rows) == 1 and rows[0].algorithm == "RSA-2048"


def test_record_probe_error(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_probe_error(
        scan_id, probe_id="net.tls.https", message="connection refused"
    )
    rows = repo.list_findings(scan_id)
    assert len(rows) == 1
    assert rows[0].classification == "error"
    assert rows[0].severity == "info"
