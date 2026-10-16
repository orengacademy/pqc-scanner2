"""Enroll → ingest → fleet view, with every rejection path."""
import os

import pytest
from fastapi.testclient import TestClient
from loguru import logger
from sqlalchemy.exc import IntegrityError

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.daemon import fleet
from pqcscan.daemon.app import create_app
from pqcscan.daemon.fleet import hash_token
from pqcscan.store.bundle import HostIdentity, dump_bundle
from pqcscan.store.repo import Repo

HOST = {"machine_id": "m-1", "hostname": "web01", "os": "linux", "labels": {"env": "prod"}, "agent_version": "x"}


def _client(tmp_db_path, fast_registry, **kw):
    return TestClient(create_app(db_path=tmp_db_path, registry=fast_registry, enroll_token="ENROLL", **kw),
                      base_url="http://127.0.0.1")


def _bundle(tmp_path, machine_id="m-1", status="done"):
    src = Repo(tmp_path / f"src-{os.urandom(4).hex()}.db")
    src.init_schema()
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
    src.record_finding(sid, Finding(probe_id="fs.cert.x509", algorithm="RSA-2048",
                                    classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT, title="t"))
    if status != "running":
        src.finish_scan(sid, status=status)
    return dump_bundle(src, sid, HostIdentity(machine_id=machine_id, hostname="web01", os="linux",
                                              labels={"env": "prod"}, agent_version="x"))


def _hdr(tok):
    return {"authorization": f"Bearer {tok}", "content-type": "application/gzip"}


def _enroll(c):
    r = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": HOST})
    assert r.status_code == 201, r.text
    return r.json()


def test_enroll_then_ingest_then_fleet(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)
    assert tok["agent_token"] and tok["host_id"] == 1
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok["agent_token"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stored_findings"] == 1 and body["duplicate"] is False
    fleet_json = c.get("/api/fleet").json()
    assert fleet_json[0]["hostname"] == "web01" and fleet_json[0]["crit"] == 1
    assert fleet_json[0]["labels"] == {"env": "prod"}
    hist = c.get("/api/fleet/1").json()
    assert hist["host"]["machine_id"] == "m-1" and len(hist["scans"]) == 1
    assert c.get("/api/fleet/99").status_code == 404
    # token is stored hashed
    assert Repo(tmp_db_path).get_host_by_token_hash(hash_token(tok["agent_token"])).id == 1


def test_enroll_rejections(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    assert c.post("/api/agents/enroll", json={"enroll_token": "nope", "host": HOST}).status_code == 403
    assert c.post("/api/agents/enroll", json={"host": HOST}).status_code == 403
    assert c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": {}}).status_code == 400
    assert c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": "x"}).status_code == 400
    no_enroll = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry), base_url="http://127.0.0.1")
    assert no_enroll.post("/api/agents/enroll", json={"enroll_token": "x", "host": HOST}).status_code == 503


def test_ingest_rejections(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    monkeypatch.setattr(fleet, "INGEST_BURST", 1)
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    h = _hdr(tok)
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers={"content-type": "application/gzip"}).status_code == 401
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr("bad")).status_code == 401
    assert c.post("/api/ingest", content=b"garbage", headers=h).status_code == 400
    assert c.post("/api/ingest", content=_bundle(tmp_path, machine_id="other"), headers=h).status_code == 403
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 200
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 429   # bucket empty
    # incompressible body so the wire size, not the decompressed size, trips the cap
    assert c.post("/api/ingest", content=os.urandom(9 * 1024 * 1024), headers=h).status_code == 413


def test_revoked_token_is_401(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    assert c.post("/api/agents/1/revoke").json() == {"revoked": True}
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 401
    assert c.post("/api/agents/99/revoke").status_code == 404


def test_fleet_paths_bypass_site_cookie_guard(tmp_db_path, fast_registry, tmp_path):
    # Site token set: /api/fleet needs it, but enroll/ingest use the agent token only.
    c = _client(tmp_db_path, fast_registry, token="SITE")
    assert c.get("/api/fleet").status_code == 401
    assert c.get("/api/fleet", headers={"authorization": "Bearer SITE"}).status_code == 200
    tok = _enroll(c)["agent_token"]
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 200


def test_ingest_ignores_session_cookie(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry, token="SITE")
    c.post("/login", data={"token": "SITE"}, follow_redirects=False)   # session cookie now set
    assert c.cookies
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers={"content-type": "application/gzip"})
    assert r.status_code == 401


@pytest.mark.parametrize("exc", [ValueError("scan_uuid belongs to another host"), KeyError("probe_id"),
                                 TypeError("bad finding")])
def test_ingest_malformed_content_is_400(tmp_db_path, fast_registry, tmp_path, monkeypatch, exc):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]

    def boom(self, bundle, host_id):
        raise exc
    monkeypatch.setattr(Repo, "ingest_bundle", boom)
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok))
    assert r.status_code == 400
    assert str(exc.args[0]) in r.json()["detail"] and "Error(" not in r.json()["detail"]   # message, not repr


def test_concurrent_duplicate_scan_uuid_is_200_duplicate(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    real = Repo.ingest_bundle

    def lose_race(self, bundle, host_id):
        real(self, bundle, host_id)   # the "other" request stored it first...
        raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed: scans.scan_uuid"))  # ...ours lost
    monkeypatch.setattr(Repo, "ingest_bundle", lose_race)
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok))
    assert r.status_code == 200, r.text
    assert r.json() == {"scan_id": 1, "stored_findings": 0, "stored_views": 0, "duplicate": True}


def test_non_terminal_status_is_400(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    r = c.post("/api/ingest", content=_bundle(tmp_path, status="running"), headers=_hdr(tok))
    assert r.status_code == 400 and "status" in r.json()["detail"]
    monkeypatch.setattr(fleet, "INGEST_MIN_INTERVAL_S", 0.0)
    for status in ("failed", "interrupted"):
        assert c.post("/api/ingest", content=_bundle(tmp_path, status=status), headers=_hdr(tok)).status_code == 200


def test_reenroll_logs_warning_and_rotates_token(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    seen: list[str] = []
    sink = logger.add(lambda m: seen.append(str(m)), level="WARNING")
    try:
        first = _enroll(c)
        assert not seen                                   # first enrollment is not a rotation
        second = _enroll(c)
    finally:
        logger.remove(sink)
    assert second["host_id"] == first["host_id"] and second["agent_token"] != first["agent_token"]
    assert len(seen) == 1 and "rotated" in seen[0] and "m-1" in seen[0] and "web01" in seen[0]
    repo = Repo(tmp_db_path)
    assert repo.get_host_by_token_hash(hash_token(first["agent_token"])) is None
    assert repo.get_host_by_token_hash(hash_token(second["agent_token"])).id == 1


def test_rate_limit_interval_read_at_request_time(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    c = _client(tmp_db_path, fast_registry)           # router built BEFORE the patch
    tok = _enroll(c)["agent_token"]
    monkeypatch.setattr(fleet, "INGEST_MIN_INTERVAL_S", 0.0)
    data = _bundle(tmp_path)
    assert c.post("/api/ingest", content=data, headers=_hdr(tok)).status_code == 200
    r = c.post("/api/ingest", content=data, headers=_hdr(tok))
    assert r.status_code == 200 and r.json()["duplicate"] is True


def test_token_bucket_burst_and_no_spend_on_duplicate_or_rejection(tmp_db_path, fast_registry, tmp_path,
                                                                   monkeypatch):
    monkeypatch.setattr(fleet, "INGEST_BURST", 2)
    c = _client(tmp_db_path, fast_registry)
    h = _hdr(_enroll(c)["agent_token"])
    a = _bundle(tmp_path)
    assert c.post("/api/ingest", content=a, headers=h).status_code == 200
    for _ in range(3):                                            # resends are free
        r = c.post("/api/ingest", content=a, headers=h)
        assert r.status_code == 200 and r.json()["duplicate"] is True
    real = Repo.ingest_bundle
    monkeypatch.setattr(Repo, "ingest_bundle", lambda self, b, hid: (_ for _ in ()).throw(ValueError("bad")))
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 400   # refunded
    monkeypatch.setattr(Repo, "ingest_bundle", real)
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 200   # second token
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 429


def test_chunked_oversize_upload_is_413(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]

    def body():                       # generator body => chunked, no Content-Length to pre-check
        for _ in range(9):
            yield os.urandom(1024 * 1024)
    assert c.post("/api/ingest", content=body(), headers=_hdr(tok)).status_code == 413


def test_revoked_host_cannot_reenroll_until_unrevoked(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    _enroll(c)
    assert c.post("/api/agents/1/revoke").status_code == 200
    r = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": HOST})
    assert r.status_code == 403 and "unrevoke 1" in r.json()["detail"]
    repo = Repo(tmp_db_path)
    assert repo.get_host(1).token_hash is None and repo.get_host(1).revoked is True
    assert repo.unrevoke_host(1) is True
    again = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": HOST})
    assert again.status_code == 201
    assert repo.get_host(1).revoked is False


@pytest.mark.parametrize("path", ["/api/ingest", "/api/agents/enroll"])
def test_exempt_paths_keep_host_and_origin_guards(tmp_db_path, fast_registry, path):
    c = _client(tmp_db_path, fast_registry, token="SITE")
    body = {"enroll_token": "ENROLL", "host": HOST}
    assert c.post(path, json=body, headers={"host": "evil.example"}).status_code == 400
    assert c.post(path, json=body, headers={"origin": "http://evil.example"}).status_code == 403
