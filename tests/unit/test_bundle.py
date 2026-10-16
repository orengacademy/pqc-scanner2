"""ScanBundle round-trip: everything a host scan produced survives dump -> load."""
import gzip
import json
from datetime import date

import pytest

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import (
    MAX_GZIP_BYTES,
    BundleInvalid,
    BundleTooLarge,
    HostIdentity,
    dump_bundle,
    load_bundle,
)
from pqcscan.store.repo import Repo

HOST = HostIdentity(machine_id="m-1", hostname="web01", os="linux",
                    labels={"env": "prod"}, agent_version="0.10.0")


def _seed(repo: Repo) -> int:
    sid = repo.create_scan(mode="root", probe_versions={"p": "1"}, tool_versions={})
    fid = repo.record_finding(sid, Finding(
        probe_id="fs.cert.x509", algorithm="RSA-2048", classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT, title="weak cert", evidence={"path": "/etc/x.pem"},
        remediation={"replacement": "ML-DSA-65"},
    ))
    repo.record_framework_view(fid, framework="cnsa2", clause="CNSA2:RSA", verdict="non-compliant",
                               deadline=date(2030, 12, 31))
    repo.record_probe_error(sid, probe_id="net.tls.https", message="timeout")
    repo.finish_scan(sid, status="done")
    return sid


def test_round_trip(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    sid = _seed(repo)
    data = dump_bundle(repo, sid, HOST)
    b = load_bundle(data)
    assert b.schema_version == 1
    assert b.scan_uuid == repo.get_scan(sid).scan_uuid
    assert b.host == HOST
    assert b.scan["status"] == "done" and b.scan["mode"] == "root"
    assert b.scan["probe_versions"] == {"p": "1"}
    assert len(b.findings) == 2                             # finding + probe-error row
    f = next(x for x in b.findings if x["probe_id"] == "fs.cert.x509")
    assert f["evidence"] == {"path": "/etc/x.pem"} and f["classification"] == "sangat-tinggi"
    assert f["views"] == [{"framework": "cnsa2", "clause": "CNSA2:RSA",
                           "verdict": "non-compliant", "deadline": "2030-12-31"}]


def test_is_gzip_json(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    data = dump_bundle(repo, _seed(repo), HOST)
    doc = json.loads(gzip.decompress(data))
    assert doc["schema_version"] == 1 and doc["host"]["machine_id"] == "m-1"


def test_load_rejects_garbage_and_wrong_version():
    with pytest.raises(BundleInvalid):
        load_bundle(b"not gzip")
    with pytest.raises(BundleInvalid):
        load_bundle(gzip.compress(json.dumps({"schema_version": 99}).encode()))


def test_load_rejects_oversize():
    with pytest.raises(BundleTooLarge):
        load_bundle(b"\x1f\x8b" + b"\x00" * (MAX_GZIP_BYTES + 1))
    zeros = gzip.compress(b"{" + b" " * (50 * 1024 * 1024 + 10) + b"}")
    with pytest.raises(BundleTooLarge):
        load_bundle(zeros)
