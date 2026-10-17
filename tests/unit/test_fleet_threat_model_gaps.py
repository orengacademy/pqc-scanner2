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


# --- rows that pin an accepted risk or a documented gap (E7, X5, X6, D6, S5, T5) and one that checks a control (I10).
# A pinning test passes today because the residual risk in docs/security/THREAT-MODEL-FLEET.md is true. If a control
# is added later, the test fails on purpose: change the test and the row together.


def test_e7_token_holder_can_enroll_without_limit(tmp_db_path, fast_registry):
    """E7 / AR2: no cap and no throttle on enrollment; every distinct machine id gets a host row and a token."""
    c = _client(tmp_db_path, fast_registry)
    codes = [c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": {**HOST, "machine_id": f"m-{i}"}}
                    ).status_code for i in range(150)]
    assert set(codes) == {201}                      # no 429, no 503, no quota
    assert len(Repo(tmp_db_path).list_hosts()) == 150
    # Without the enroll token nothing is written, so rotating it (the operator remedy) stops the growth.
    bad = c.post("/api/agents/enroll", json={"enroll_token": "OLD", "host": {**HOST, "machine_id": "m-new"}})
    assert bad.status_code == 403 and len(Repo(tmp_db_path).list_hosts()) == 150


def _fleet_of(c, tmp_path, start, stop):
    for i in range(start, stop):
        mid = f"m-{i}"
        tok = c.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": {**HOST, "machine_id": mid}}
                     ).json()["agent_token"]
        assert c.post("/api/ingest", content=_bundle(tmp_path, machine_id=mid), headers=_hdr(tok)
                      ).status_code == 200


def test_x5_fleet_export_scales_linearly_and_the_rollup_is_removed(tmp_db_path, fast_registry, tmp_path):
    """X5: the export has a render-slot cap (test_daemon_guard) but no size bound. At toy size the output doubles
    when the fleet doubles and peak memory stays within 3x. Memory at 2,000 hosts is not measured here."""
    import tracemalloc

    c = _client(tmp_db_path, fast_registry)
    size, peak = {}, {}
    for n in (30, 60):
        _fleet_of(c, tmp_path, len(Repo(tmp_db_path).list_hosts()), n)
        before = len(Repo(tmp_db_path).list_scans())
        tracemalloc.start()
        try:
            r = c.get("/api/scans/fleet/export/cbom")
            peak[n] = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert r.status_code == 200
        size[n] = len(r.content)
        assert len(Repo(tmp_db_path).list_scans()) == before        # the temporary rollup scan is gone
    assert 1.5 < size[60] / size[30] < 2.5, size
    assert peak[60] < 3 * peak[30], peak


@pytest.mark.asyncio
async def test_x5_a_slow_fleet_export_does_not_block_other_requests(tmp_db_path, fast_registry, tmp_path, monkeypatch):
    """X5: the render runs off the event loop, so a long export leaves /api/health answering."""
    import asyncio
    import time

    import httpx

    from pqcscan.cbom import builder

    def slow_cbom(repo, scan_id):
        time.sleep(1.5)
        return {"bomFormat": "CycloneDX"}

    monkeypatch.setattr(builder, "build_cbom", slow_cbom)
    app = create_app(db_path=tmp_db_path, registry=fast_registry, enroll_token="ENROLL")
    await asyncio.to_thread(_fleet_of, _client(tmp_db_path, fast_registry), tmp_path, 0, 2)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as ac:
        export = asyncio.create_task(ac.get("/api/scans/fleet/export/cbom"))
        await asyncio.sleep(0.3)                                 # the render is now sleeping in its worker thread
        t0 = time.perf_counter()
        health = await ac.get("/api/health")
        waited = time.perf_counter() - t0
        assert not export.done()
        assert health.status_code == 200 and waited < 1.0, waited
        assert (await export).status_code == 200


def test_x6_fleet_export_leaves_no_audit_record(tmp_db_path, fast_registry, tmp_path):
    """X6: nothing records who exported what: no log line mentions the export and the store has no audit table."""
    from loguru import logger
    from sqlalchemy import inspect

    c = _client(tmp_db_path, fast_registry, token="SITE")
    _fleet_of(c, tmp_path, 0, 2)
    lines: list[str] = []
    sink = logger.add(lambda m: lines.append(str(m)), level="DEBUG")
    try:
        r = c.get("/api/scans/fleet/export/cbom", headers={"authorization": "Bearer SITE"})
    finally:
        logger.remove(sink)
    assert r.status_code == 200
    assert not [ln for ln in lines if "export" in ln.lower() or "SITE" in ln], lines
    tables = set(inspect(Repo(tmp_db_path).engine).get_table_names())
    assert not [t for t in tables if any(w in t for w in ("audit", "export", "access", "event"))], tables


def test_t5_two_copies_of_one_token_are_one_host(tmp_db_path, fast_registry, tmp_path):
    """T5: a leaked token used from a second address is indistinguishable from the real agent: one host row, and
    neither the hosts table nor the fleet API records where a bundle came from."""
    from sqlalchemy import inspect

    app = create_app(db_path=tmp_db_path, registry=fast_registry, enroll_token="ENROLL", token="SITE")
    real = TestClient(app, base_url="http://127.0.0.1", client=("10.0.0.5", 40001))
    copy = TestClient(app, base_url="http://127.0.0.1", client=("203.0.113.9", 40002))
    tok = real.post("/api/agents/enroll", json={"enroll_token": "ENROLL", "host": HOST}).json()["agent_token"]
    a, b = _bundle(tmp_path), _bundle(tmp_path)
    assert real.post("/api/ingest", content=a, headers=_hdr(tok)).status_code == 200
    assert copy.post("/api/ingest", content=b, headers=_hdr(tok)).status_code == 200
    repo = Repo(tmp_db_path)
    assert len(repo.list_hosts()) == 1 and len(repo.host_history(1)) == 2
    cols = {c["name"] for t in ("hosts", "scans") for c in inspect(repo.engine).get_columns(t)}
    assert not [c for c in cols if any(w in c for w in ("addr", "ip", "remote", "client", "source", "origin"))], cols
    row = real.get("/api/fleet", headers={"authorization": "Bearer SITE"}).json()[0]
    assert "10.0.0.5" not in json.dumps(row) and "203.0.113.9" not in json.dumps(row)


def test_s5_spool_has_no_size_or_age_cap(tmp_path):
    """S5: during an outage every cycle adds a bundle and nothing is ever dropped (the operator watches the disk)."""
    from pqcscan.cli import _report

    state = tmp_path / "state"
    names = [_report.spool_bundle(state, b"x" * 4096).name for _ in range(300)]
    kept = sorted((state / _report.SPOOL_DIR).iterdir())
    assert len(kept) == 300 and len(set(names)) == 300            # nothing evicted, nothing overwritten
    assert sum(p.stat().st_size for p in kept) == 300 * 4096


def test_d6_agent_keeps_no_local_record_of_what_it_sent(tmp_path, tmp_db_path, fast_registry, monkeypatch):
    """D6: after a successful report the state dir holds the token and nothing else, and the send logs nothing."""
    import httpx
    from loguru import logger

    from pqcscan.cli import _report

    monkeypatch.setenv("PQCSCAN_TEST_MACHINE_ID", "m-agent")
    agent = Repo(tmp_path / "agent.db")
    agent.init_schema()
    sid = agent.create_scan(mode="user", probe_versions={}, tool_versions={})
    agent.finish_scan(sid, status="done")
    state = tmp_path / "state"
    up = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry, enroll_token="ENROLL"),
                    base_url="http://127.0.0.1")
    lines: list[str] = []
    sink = logger.add(lambda m: lines.append(str(m)), level="DEBUG")
    try:
        sent = _report.report_scan(agent, sid, server="http://127.0.0.1", enroll_token="ENROLL", agent_token=None,
                                   labels={}, state_dir=state, client=up, allow_http=True)
    finally:
        logger.remove(sink)
    assert sent is not None
    assert sorted(p.name for p in state.rglob("*")) == [_report.TOKEN_FILE]     # no copy, no manifest, no log file
    assert not [ln for ln in lines if "WARNING" in ln or "ERROR" in ln], lines
    # a failed send, by contrast, is recorded (and spooled), so only the success path leaves nothing
    down = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(503, json={"detail": "down"})))
    assert _report.report_scan(agent, sid, server="http://127.0.0.1", enroll_token="ENROLL", agent_token=None,
                               labels={}, state_dir=state, client=down, allow_http=True) is None
    assert len(list((state / _report.SPOOL_DIR).iterdir())) == 1


def test_i10_probe_findings_carry_no_key_material_to_the_collector(tmp_db_path, fast_registry, tmp_path):
    """I10: real probes run over a directory holding a private key, an encrypted key, a PKCS#12 keystore and a JWT
    secret. Nothing secret appears in the bundle the agent builds or in what the collector stores."""
    import asyncio
    import base64
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    from pqcscan.probes._base import ScanContext
    from pqcscan.probes.app_jwt_env_alg import AppJwtEnvAlg
    from pqcscan.probes.fs_cert_privkey import FsCertPrivkey
    from pqcscan.probes.fs_cert_privkey_encrypted import FsCertPrivkeyEncrypted
    from pqcscan.probes.fs_keystore_pkcs12 import FsKeystorePkcs12
    from pqcscan.store.bundle import HostIdentity, dump_bundle

    d = tmp_path / "secrets"
    d.mkdir()
    key = rsa.generate_private_key(65537, 2048)
    plain = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    sealed = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(b"EncPass-9f3a"))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.datetime(2025, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1)).sign(key, hashes.SHA256()))
    p12 = pkcs12.serialize_key_and_certificates(b"k", key, cert, None, ser.BestAvailableEncryption(b"P12Pass-77c1"))
    (d / "k.key").write_bytes(plain)
    (d / "sealed.key").write_bytes(sealed)
    (d / "store.p12").write_bytes(p12)
    (d / ".env").write_text("JWT_ALGORITHM=HS256\nJWT_SECRET=jwt-secret-Zq81xv\n")
    body = lambda pem: [ln for ln in pem.decode().splitlines() if "-----" not in ln][1]  # noqa: E731  one body line
    secrets = [body(plain), body(sealed), base64.b64encode(p12[:48]).decode(),
               "EncPass-9f3a", "P12Pass-77c1", "jwt-secret-Zq81xv"]
    secrets = [s for s in secrets if len(s) >= 12]
    assert len(secrets) == 6

    src = Repo(tmp_path / "agent.db")
    src.init_schema()
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
    ctx = ScanContext(scan_id=sid, mode="user", available_capabilities=set())
    emitted: list = []

    async def run_probes():
        for probe in (FsCertPrivkey, FsCertPrivkeyEncrypted, FsKeystorePkcs12, AppJwtEnvAlg):
            before = len(emitted)
            await probe(roots=[d]).run(ctx, emit=emitted.append)
            assert len(emitted) > before, f"{probe.__name__} found nothing: the test would be vacuous"

    asyncio.run(run_probes())
    for f in emitted:
        src.record_finding(sid, f)
    src.finish_scan(sid, status="done")
    blob = dump_bundle(src, sid, HostIdentity(machine_id="m-1", hostname="web01", os="linux", labels={},
                                              agent_version="x"))
    assert not [s for s in secrets if s in gzip.decompress(blob).decode()]

    c = _client(tmp_db_path, fast_registry)
    assert c.post("/api/ingest", content=blob, headers=_hdr(_enroll(c)["agent_token"])).status_code == 200
    repo = Repo(tmp_db_path)
    stored = json.dumps([[f.title, f.algorithm, f.evidence] for s in repo.list_scans()
                         for f in repo.list_findings(s.id)], default=str)
    assert len(stored) > 100 and not [s for s in secrets if s in stored]
