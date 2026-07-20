import json

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.renderers.sarif import build_sarif, render_sarif
from pqcscan.store.repo import Repo


def _seed(repo: Repo) -> int:
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.kex_groups",
        algorithm="RSA-2048",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="RSA-2048 key establishment",
        evidence={"path": "/etc/nginx/nginx.conf"},
        remediation={"replacement": "ML-KEM-768", "deadline": "2030-01-01", "hndl": True},
    ))
    repo.record_finding(scan_id, Finding(
        probe_id="fs.cert.x509",
        algorithm="ECDSA-SHA256",
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title="ECDSA leaf cert",
    ))
    repo.finish_scan(scan_id, status="done")
    return scan_id


def test_sarif_structure(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    doc = build_sarif(repo, scan_id)

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pqcscan"
    # Two distinct probes -> two rules.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"net.tls.kex_groups", "fs.cert.x509"}
    assert len(run["results"]) == 2


def test_sarif_level_and_security_severity(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    results = build_sarif(repo, scan_id)["runs"][0]["results"]
    crit = next(r for r in results if r["ruleId"] == "net.tls.kex_groups")
    assert crit["level"] == "error"
    assert crit["properties"]["security-severity"] == "9.5"
    assert crit["properties"]["pqc_replacement"] == "ML-KEM-768"
    assert crit["properties"]["harvest_now_decrypt_later"] is True
    assert "→ migrate to ML-KEM-768 by 2030-01-01" in crit["message"]["text"]


def test_sarif_physical_location_from_path(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    results = build_sarif(repo, scan_id)["runs"][0]["results"]
    crit = next(r for r in results if r["ruleId"] == "net.tls.kex_groups")
    uri = crit["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "file:///etc/nginx/nginx.conf"
    # The finding with no path has no locations.
    ec = next(r for r in results if r["ruleId"] == "fs.cert.x509")
    assert "locations" not in ec


def test_sarif_rule_index_consistency(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    run = build_sarif(repo, scan_id)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_render_sarif_writes_valid_json(tmp_db_path, tmp_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    out = tmp_path / "out.sarif"
    render_sarif(repo, scan_id, out)
    doc = json.loads(out.read_text())
    assert doc["$schema"].endswith("sarif-2.1.0.json")
