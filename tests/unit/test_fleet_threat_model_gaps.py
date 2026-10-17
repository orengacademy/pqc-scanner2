"""Abuse cases from docs/security/THREAT-MODEL-FLEET.md that no other test pinned down."""
import gzip
import json
import os
import stat

import pytest
from fastapi.testclient import TestClient

from pqcscan.cli._report import spool_bundle
from pqcscan.daemon.app import create_app
from pqcscan.store.repo import Repo

from .test_daemon_fleet import HOST, _bundle, _client, _enroll, _hdr


def _as_machine(blob: bytes, machine_id: str) -> bytes:
    doc = json.loads(gzip.decompress(blob))
    doc["host"]["machine_id"] = machine_id
    return gzip.compress(json.dumps(doc).encode())


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/fleet"), ("GET", "/api/fleet/1"), ("POST", "/api/agents/1/revoke"),
    ("GET", "/api/scans/fleet/export/cbom"), ("GET", "/api/scans"),
])
def test_agent_token_is_not_a_site_credential(tmp_db_path, fast_registry, method, path):
    c = _client(tmp_db_path, fast_registry, token="SITE")
    agent = _enroll(c)["agent_token"]
    r = c.request(method, path, headers={"authorization": f"Bearer {agent}"})
    assert r.status_code == 401
    assert c.get("/api/fleet", headers={"authorization": "Bearer SITE"}).json()[0]["revoked"] is False


def test_fleet_export_and_pages_need_the_site_token(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry, token="SITE")
    assert c.get("/api/scans/fleet/export/cbom").status_code == 401
    assert c.get("/fleet", headers={"accept": "application/json"}).status_code == 401


@pytest.mark.parametrize("path", ["/api/ingest/", "/api/agents/enroll/", "/api//ingest", "/API/ingest"])
def test_bearer_bypass_is_exact_for_the_two_fleet_paths(tmp_db_path, fast_registry, tmp_path, path):
    c = _client(tmp_db_path, fast_registry, token="SITE")
    agent = _enroll(c)["agent_token"]
    r = c.post(path, content=_bundle(tmp_path), headers=_hdr(agent))
    assert r.status_code in (401, 404, 405)
    assert not Repo(tmp_db_path).list_scans()


@pytest.mark.parametrize("presented", [["ENROLL"], 0, {"a": 1}, True, None, "ENROLL ", "enroll", "ENROLL\x00"])
def test_enroll_token_must_match_exactly(tmp_db_path, fast_registry, presented):
    c = _client(tmp_db_path, fast_registry)
    r = c.post("/api/agents/enroll", json={"enroll_token": presented, "host": HOST})
    assert r.status_code == 403
    assert Repo(tmp_db_path).get_host_by_machine_id(HOST["machine_id"]) is None


def test_scan_uuid_cannot_be_taken_over_by_another_host(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    a = _enroll(c)["agent_token"]
    blob = _bundle(tmp_path, machine_id="m-1")
    assert c.post("/api/ingest", content=blob, headers=_hdr(a)).status_code == 200
    other = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": {**HOST, "machine_id": "m-2"}})
    b = other.json()["agent_token"]
    r = c.post("/api/ingest", content=_as_machine(blob, "m-2"), headers=_hdr(b))   # same scan_uuid, other host
    assert r.status_code == 400 and "another host" in r.text
    assert len(Repo(tmp_db_path).host_history(1)) == 1 and not Repo(tmp_db_path).host_history(2)


def test_one_hosts_token_cannot_post_as_another_host(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    a = _enroll(c)["agent_token"]
    c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": {**HOST, "machine_id": "m-2"}})
    r = c.post("/api/ingest", content=_bundle(tmp_path, machine_id="m-2"), headers=_hdr(a))
    assert r.status_code == 403
    assert not Repo(tmp_db_path).host_history(2)


def test_spooled_bundle_file_is_owner_only(tmp_path):
    p = spool_bundle(tmp_path / "state", b"bundle")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(p.parent).st_mode) == 0o700


def test_unknown_host_header_is_rejected_before_any_auth(tmp_db_path, fast_registry):
    app = create_app(db_path=tmp_db_path, registry=fast_registry, token="SITE", enroll_token="ENROLL")
    c = TestClient(app, base_url="http://127.0.0.1")
    assert c.get("/api/fleet", headers={"host": "rebind.example", "authorization": "Bearer SITE"}).status_code == 400
