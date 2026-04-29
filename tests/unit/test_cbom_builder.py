from pqcscan.cbom.builder import build_cbom
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.repo import Repo


def test_build_cbom_minimal_shape(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="RSA-2048",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="server cert uses RSA-2048",
        evidence={"endpoint": "127.0.0.1:443"},
    ))
    repo.finish_scan(scan_id, status="done")

    cbom = build_cbom(repo, scan_id)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert "metadata" in cbom and "tools" in cbom["metadata"]
    assert any(c.get("type") == "cryptographic-asset" for c in cbom["components"])
    names = [c["name"] for c in cbom["components"]]
    assert any("RSA-2048" in n for n in names)


def test_build_cbom_skips_na_algorithm(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_finding(scan_id, Finding(
        probe_id="aux.clock.cert_validity",
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title="clock at scan",
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    assert cbom["components"] == []


def test_build_cbom_includes_pqc_ready(tmp_db_path):
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = repo.create_scan(
        mode="user", probe_versions={}, tool_versions={}
    )
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="ML-KEM-768",
        classification=Classification.PQC_READY,
        severity=Severity.INFO,
        title="hybrid PQC kex",
    ))
    repo.finish_scan(scan_id, status="done")
    cbom = build_cbom(repo, scan_id)
    levels = [
        c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        for c in cbom["components"]
    ]
    assert max(levels) >= 3
