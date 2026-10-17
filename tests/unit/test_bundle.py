"""ScanBundle round-trip: everything a host scan produced survives dump -> load."""
import gzip
import json
from datetime import date

import pytest

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import (
    MAX_FINDINGS,
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


def test_load_rejects_truncated_gzip():
    blob = gzip.compress(json.dumps({"schema_version": 1, "scan_uuid": "u", "host": {"machine_id": "m"},
                                     "scan": {}, "findings": []}).encode())
    assert load_bundle(blob).scan_uuid == "u"
    for cut in (1, 4, 8, 9):            # inside the CRC/length trailer, and just past the deflate data
        with pytest.raises(BundleInvalid, match="truncated"):
            load_bundle(blob[:-cut])


def test_load_ignores_bytes_after_the_gzip_member():
    # pins the end-of-stream rule: a complete first member is what counts, whatever follows it
    blob = gzip.compress(json.dumps({"schema_version": 1, "scan_uuid": "u", "host": {"machine_id": "m"},
                                     "scan": {}, "findings": []}).encode())
    assert load_bundle(blob + b"trailing garbage").scan_uuid == "u"
    assert load_bundle(blob + gzip.compress(b"{}")).scan_uuid == "u"       # a second member is not read


def test_load_rejects_oversize():
    with pytest.raises(BundleTooLarge):
        load_bundle(b"\x1f\x8b" + b"\x00" * (MAX_GZIP_BYTES + 1))
    zeros = gzip.compress(b"{" + b" " * (50 * 1024 * 1024 + 10) + b"}")
    with pytest.raises(BundleTooLarge):
        load_bundle(zeros)


def _doc(**over):
    d = {"schema_version": 1, "scan_uuid": "u", "host": {"machine_id": "m"}, "scan": {}, "findings": []}
    d.update(over)
    return gzip.compress(json.dumps(d).encode())


def test_load_accepts_minimal_valid_doc():
    assert load_bundle(_doc()).host.labels == {}


def test_load_strips_server_only_evidence_keys():
    fs = [{"evidence": {"host": "bank.example", "_fleet": {"host": "evil", "machine_id": "x"}, "path": "/a"}},
          {"title": "no evidence"}, {"evidence": "not a dict"}]
    got = load_bundle(_doc(findings=fs)).findings
    assert got == [{"evidence": {"host": "bank.example", "path": "/a"}}, {"title": "no evidence"},
                   {"evidence": "not a dict"}]


@pytest.mark.parametrize("over", [
    {"findings": "nope"},
    {"findings": ["a string"]},
    {"host": {"machine_id": "m", "labels": ["x"]}},
    {"host": "web01"},
    {"scan": "abc"},
    {"findings": {}},
    {"host": {"machine_id": "m", "labels": 0}},
    {"host": {"machine_id": "m", "labels": {"a": {"b": 1}}}},
    {"scan_uuid": None},
    {"scan_uuid": ""},
    {"scan_uuid": 7},
    {"host": {"machine_id": None}},
    {"host": {"machine_id": ""}},
    {"host": {}},
    {"host": {"machine_id": "m", "hostname": 5}},
    {"host": {"machine_id": "m", "hostname": None}},
    {"host": {"machine_id": "m", "os": 1}},
    {"host": {"machine_id": "m", "agent_version": []}},
])
def test_load_rejects_malformed_structure(over):
    with pytest.raises(BundleInvalid):
        load_bundle(_doc(**over))


def test_load_rejects_too_many_findings():
    with pytest.raises(BundleTooLarge):
        load_bundle(_doc(findings=[{}] * (MAX_FINDINGS + 1)))


def test_load_rejects_deeply_nested_json():
    with pytest.raises(BundleInvalid):
        load_bundle(gzip.compress(b"[" * 2000 + b"]" * 2000))


def test_load_accepts_empty_optional_identity_fields():
    b = load_bundle(_doc(host={"machine_id": "m", "hostname": "", "os": "", "agent_version": "", "labels": {}}))
    assert b.host.hostname == "" and b.host.machine_id == "m" and b.scan_uuid == "u"


def test_load_drops_agent_sent_fleet_drift_findings():
    fs = [{"probe_id": "fs.cert.x509", "algorithm": "RSA-2048"},
          {"probe_id": "fleet.drift", "algorithm": "RSA-1024", "evidence": {"change": "added"}}]
    b = load_bundle(_doc(findings=fs))
    assert b.findings == [{"probe_id": "fs.cert.x509", "algorithm": "RSA-2048"}] and b.dropped_drift == 1


def test_load_caps_host_labels():
    ok = {f"k{i}": "v" * 256 for i in range(64)} | {"x" * 64: "v"}
    del ok["k0"]
    assert len(load_bundle(_doc(host={"machine_id": "m", "labels": ok})).host.labels) == 64
    for bad in ({f"k{i}": "v" for i in range(65)}, {"x" * 65: "v"}, {"k": "v" * 257}):
        with pytest.raises(BundleInvalid, match=r"host\.labels"):
            load_bundle(_doc(host={"machine_id": "m", "labels": bad}))
