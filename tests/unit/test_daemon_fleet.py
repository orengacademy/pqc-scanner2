"""Enroll → ingest → fleet view, with every rejection path."""
import gzip
import json
import os

import pytest
from fastapi.testclient import TestClient
from loguru import logger
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.requests import Request

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
    monkeypatch.setattr(fleet, "INGEST_BURST", 4)                   # 401s are free; the next four spend
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    h = _hdr(tok)
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers={"content-type": "application/gzip"}).status_code == 401
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr("bad")).status_code == 401
    assert c.post("/api/ingest", content=b"garbage", headers=h).status_code == 400
    assert c.post("/api/ingest", content=_bundle(tmp_path, machine_id="other"), headers=h).status_code == 403
    # incompressible body so the wire size, not the decompressed size, trips the cap
    assert c.post("/api/ingest", content=os.urandom(9 * 1024 * 1024), headers=h).status_code == 413
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 200
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 429   # rejections spent tokens


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


def test_rejected_store_does_not_touch_the_host_row(tmp_db_path, fast_registry, tmp_path):
    import gzip
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    doc = json.loads(gzip.decompress(_bundle(tmp_path)))
    doc["host"]["hostname"] = "renamed"
    del doc["findings"][0]["probe_id"]                     # parses, then fails inside the store
    r = c.post("/api/ingest", content=gzip.compress(json.dumps(doc).encode()), headers=_hdr(tok))
    assert r.status_code == 400
    assert Repo(tmp_db_path).get_host(1).hostname == "web01"


def test_store_busy_is_503_with_retry_after(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]

    def busy(self, bundle, host_id):
        raise OperationalError("INSERT", {}, Exception("database is locked"))
    monkeypatch.setattr(Repo, "ingest_bundle", busy)
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok))
    assert r.status_code == 503 and r.headers["retry-after"] == "5"


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


def test_ingest_prunes_to_keep(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry, keep_scans_per_host=2)
    tok = _enroll(c)["agent_token"]
    ids = [c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).json()["scan_id"] for _ in range(3)]
    kept = [s.id for s in Repo(tmp_db_path).host_history(1)]
    assert sorted(kept) == sorted(ids[1:])                  # the oldest went, the one just ingested stayed
    assert len(c.get("/api/fleet/1").json()["scans"]) == 2


def test_ingest_succeeds_when_prune_fails(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    def boom(self, host_id, keep):
        raise OperationalError("s", {}, Exception("busy"))
    monkeypatch.setattr(Repo, "prune_host", boom)
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    r = c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok))
    assert r.status_code == 200 and r.json()["duplicate"] is False       # stored scan is not reported as a failure


def test_ingest_sweeps_stale_rollups_and_logs_dropped_drift(tmp_db_path, fast_registry, tmp_path):
    from datetime import timedelta

    from sqlalchemy.orm import Session

    from pqcscan.store.schema import Scan
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 200
    repo = Repo(tmp_db_path)
    rollup = repo.materialize_fleet_rollup()             # an orphan left by a killed export, aged past the hour
    with Session(repo.engine) as s:
        s.get(Scan, rollup).started_at -= timedelta(hours=2)
        s.commit()
    doc = json.loads(gzip.decompress(_bundle(tmp_path)))
    doc["findings"].append({**doc["findings"][0], "probe_id": "fleet.drift"})
    seen: list[str] = []
    sink = logger.add(lambda m: seen.append(str(m)), level="WARNING")
    try:
        r = c.post("/api/ingest", content=gzip.compress(json.dumps(doc).encode()), headers=_hdr(tok))
    finally:
        logger.remove(sink)
    assert r.status_code == 200, r.text
    assert repo.get_scan(rollup) is None                 # swept after the prune
    assert any("dropped 1 agent-sent fleet.drift" in m and "host 1" in m for m in seen)


def test_enroll_caps_host_labels(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    for bad in ({f"k{i}": "v" for i in range(65)}, {"x" * 65: "v"}, {"k": "v" * 257}):
        r = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": {**HOST, "labels": bad}})
        assert r.status_code == 400 and "host.labels" in r.json()["detail"]
    assert Repo(tmp_db_path).get_host_by_machine_id("m-1") is None
    _enroll(c)


def test_fleet_summary_reports_drift_count(tmp_db_path, fast_registry, tmp_path):
    c = _client(tmp_db_path, fast_registry)
    tok = _enroll(c)["agent_token"]
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 200
    doc = json.loads(gzip.decompress(_bundle(tmp_path)))
    doc["findings"][0]["algorithm"] = "RSA-1024"           # one removed + one added
    sid = c.post("/api/ingest", content=gzip.compress(json.dumps(doc).encode()),
                 headers=_hdr(tok)).json()["scan_id"]
    (row,) = c.get("/api/fleet").json()
    assert row["drift"] == 2 and row["total"] == 1          # drift counted apart from the findings
    assert "drift 2" in c.get("/fleet").text
    assert "drift 2" in c.get("/fleet/1").text and Repo(tmp_db_path).drift_counts([sid - 1, sid]) == {sid: 2}


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
    monkeypatch.setattr(fleet, "INGEST_BURST", 1)
    c = _client(tmp_db_path, fast_registry)           # router built BEFORE the interval patch
    tok = _enroll(c)["agent_token"]
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 200
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 429
    monkeypatch.setattr(fleet, "INGEST_MIN_INTERVAL_S", 0.0)   # refill instantly from now on
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=_hdr(tok)).status_code == 200


def test_token_bucket_every_outcome_spends_a_token(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    monkeypatch.setattr(fleet, "INGEST_BURST", 4)
    c = _client(tmp_db_path, fast_registry)
    h = _hdr(_enroll(c)["agent_token"])
    a = _bundle(tmp_path)
    assert c.post("/api/ingest", content=a, headers=h).status_code == 200                   # token 1
    r = c.post("/api/ingest", content=a, headers=h)                                         # token 2: duplicate
    assert r.status_code == 200 and r.json()["duplicate"] is True
    real = Repo.ingest_bundle
    monkeypatch.setattr(Repo, "ingest_bundle", lambda self, b, hid: (_ for _ in ()).throw(ValueError("bad")))
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 400   # token 3: rejected
    monkeypatch.setattr(Repo, "ingest_bundle", real)
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 200   # token 4
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 429
    assert c.post("/api/ingest", content=a, headers=h).status_code == 429                   # duplicates throttled too
    assert c.post("/api/ingest", content=b"garbage", headers=h).status_code == 429          # malformed too


def test_enroll_disabled_is_503_without_parsing_the_body(tmp_db_path, fast_registry, monkeypatch):
    c = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry), base_url="http://127.0.0.1")

    def no_parse(*a, **k):
        raise AssertionError("enroll body parsed while enrollment is disabled")
    monkeypatch.setattr(json, "loads", no_parse)
    r = c.post("/api/agents/enroll", content=b"x" * (20 * 1024 * 1024), headers={"content-type": "application/json"})
    assert r.status_code == 503


def test_enroll_body_is_capped_and_must_be_a_json_object(tmp_db_path, fast_registry):
    c = _client(tmp_db_path, fast_registry)
    big = json.dumps({"enroll_token": "ENROLL", "host": HOST, "pad": "x" * fleet.MAX_ENROLL_BYTES}).encode()
    assert c.post("/api/agents/enroll", content=big).status_code == 413

    def chunked():
        yield big
    assert c.post("/api/agents/enroll", content=chunked()).status_code == 413
    assert c.post("/api/agents/enroll", content=b"not json").status_code == 400
    assert c.post("/api/agents/enroll", content=b"[1]").status_code == 400


def test_rate_limit_rejects_before_reading_the_body(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    monkeypatch.setattr(fleet, "INGEST_BURST", 1)
    c = _client(tmp_db_path, fast_registry)
    h = _hdr(_enroll(c)["agent_token"])
    assert c.post("/api/ingest", content=_bundle(tmp_path), headers=h).status_code == 200

    def no_read(self):
        raise AssertionError("ingest body read by a throttled request")
    monkeypatch.setattr(Request, "stream", no_read)
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
