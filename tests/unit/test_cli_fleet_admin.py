import json

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from pqcscan.cli.export import export_cmd
from pqcscan.cli.fleet import agents_cmd, fleet_cmd, resolve_scan_ref
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.daemon.app import create_app
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo


def _fleet_db(tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_path / "fleet.db"); fleet.init_schema()
    for name in ("web01", "web02"):
        ident = HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux")
        h = fleet.upsert_host(ident, token_hash=name)
        for _ in range(3):
            sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
            src.record_finding(sid, Finding(probe_id="p", algorithm="RSA-2048", classification=Classification.TINGGI,
                                            severity=Severity.HIGH, title=f"{name} t"))
            src.finish_scan(sid, status="done")
            fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), h.id)
    return tmp_path / "fleet.db"


def _rollups(db):
    return [s for s in Repo(db).list_scans() if s.label == "fleet-rollup"]


def test_agents_list_and_revoke(tmp_path):
    db = _fleet_db(tmp_path)
    r = CliRunner().invoke(agents_cmd, ["list", "--db", str(db), "--json"])
    assert r.exit_code == 0 and [x["hostname"] for x in json.loads(r.output)] == ["web01", "web02"]
    assert CliRunner().invoke(agents_cmd, ["revoke", "1", "--db", str(db)]).exit_code == 0
    assert Repo(db).get_host(1).revoked is True
    assert CliRunner().invoke(agents_cmd, ["revoke", "99", "--db", str(db)]).exit_code == 3


def test_agents_unrevoke(tmp_path):
    db = _fleet_db(tmp_path)
    CliRunner().invoke(agents_cmd, ["revoke", "1", "--db", str(db)])
    r = CliRunner().invoke(agents_cmd, ["unrevoke", "1", "--db", str(db)])
    assert r.exit_code == 0 and "re-enroll" in r.output
    host = Repo(db).get_host(1)
    assert host.revoked is False and host.token_hash is None
    assert CliRunner().invoke(agents_cmd, ["unrevoke", "99", "--db", str(db)]).exit_code == 3


def test_fleet_summary_and_prune(tmp_path):
    db = _fleet_db(tmp_path)
    r = CliRunner().invoke(fleet_cmd, ["summary", "--db", str(db), "--json"])
    rows = json.loads(r.output)
    assert r.exit_code == 0 and rows[0]["hostname"] == "web01" and rows[0]["high"] == 1
    r = CliRunner().invoke(fleet_cmd, ["prune", "--keep", "1", "--db", str(db)])
    assert r.exit_code == 0 and "4 scans" in r.output
    assert len(Repo(db).list_scans()) == 2


@pytest.mark.parametrize("keep", ["0", "-3"])
def test_fleet_prune_rejects_keep_below_one(tmp_path, keep):
    db = _fleet_db(tmp_path)
    r = CliRunner().invoke(fleet_cmd, ["prune", "--keep", keep, "--db", str(db)])
    assert r.exit_code == 2 and "Traceback" not in r.output and not isinstance(r.exception, ValueError)
    assert len(Repo(db).list_scans()) == 6                      # nothing deleted


def test_export_scan_fleet_materialises_and_cleans_up(tmp_path):
    db = _fleet_db(tmp_path)
    out = tmp_path / "fleet.cdx.json"
    r = CliRunner().invoke(export_cmd, ["--db", str(db), "--scan", "fleet", "--format", "cbom", "-o", str(out)])
    assert r.exit_code == 0, r.output
    names = [c["name"] for c in json.loads(out.read_text())["components"]]
    assert sum("RSA-2048" in n for n in names) == 2                      # one latest scan per host
    assert not _rollups(db)                                              # temp rollup deleted
    sid, temp = resolve_scan_ref(Repo(db), "3")
    assert (sid, temp) == (3, False)


def test_export_fleet_cleans_up_when_render_raises(tmp_path, monkeypatch):
    db = _fleet_db(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("render failed")
    monkeypatch.setattr("pqcscan.cbom.builder.build_cbom", boom)
    r = CliRunner().invoke(export_cmd, ["--db", str(db), "--scan", " FLEET ", "--format", "cbom",
                                        "-o", str(tmp_path / "x.json")])
    assert r.exit_code != 0 and isinstance(r.exception, RuntimeError)
    assert not _rollups(db)


def test_export_numeric_scan_unchanged(tmp_path):
    db = _fleet_db(tmp_path)
    runner = CliRunner()
    assert runner.invoke(export_cmd, ["--db", str(db), "--scan", "999", "--format", "cbom",
                                      "-o", str(tmp_path / "x.json")]).exit_code == 3
    assert runner.invoke(export_cmd, ["--db", str(db), "--scan", "bogus", "--format", "cbom",
                                      "-o", str(tmp_path / "x.json")]).exit_code == 2
    assert runner.invoke(export_cmd, ["--db", str(db), "--scan", "1", "--format", "cbom",
                                      "-o", str(tmp_path / "x.json")]).exit_code == 0
    assert not _rollups(db)


def test_export_fleet_with_no_hosts_errors_cleanly(tmp_path):
    db = tmp_path / "empty.db"
    Repo(db).init_schema()
    r = CliRunner().invoke(export_cmd, ["--db", str(db), "--scan", "fleet", "--format", "cbom",
                                        "-o", str(tmp_path / "x.json")])
    assert r.exit_code == 1 and "no enrolled hosts with a completed scan" in r.output


def test_daemon_export_fleet(tmp_db_path, fast_registry, monkeypatch):
    app = create_app(db_path=tmp_db_path, registry=fast_registry)
    c = TestClient(app, base_url="http://127.0.0.1")
    repo = app.state.repo
    r = c.get("/api/scans/fleet/export/cbom")                      # no hosts yet
    assert r.status_code == 404 and "no enrolled hosts with a completed scan" in r.text
    assert not _rollups(tmp_db_path)

    src = Repo(tmp_db_path.parent / "src.db"); src.init_schema()
    for name in ("web01", "web02"):
        ident = HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux")
        h = repo.upsert_host(ident, token_hash=name)
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        src.record_finding(sid, Finding(probe_id="p", algorithm="RSA-2048", classification=Classification.TINGGI,
                                        severity=Severity.HIGH, title=f"{name} t"))
        src.finish_scan(sid, status="done")
        repo.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), h.id)
    r = c.get("/api/scans/FLEET/export/cbom")
    assert r.status_code == 200
    assert sum("RSA-2048" in x["name"] for x in r.json()["components"]) == 2
    assert not _rollups(tmp_db_path)

    def boom(*a, **k):
        raise RuntimeError("render failed")
    monkeypatch.setattr("pqcscan.cbom.builder.build_cbom", boom)
    with pytest.raises(RuntimeError):
        TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=True).get(
            "/api/scans/fleet/export/cbom")
    assert not _rollups(tmp_db_path)                               # cleaned even though rendering raised
    assert app.state.render_slots.acquire(blocking=False)          # slot released too
    app.state.render_slots.release()

    assert c.get("/api/scans/999/export/cbom").status_code == 404
    assert c.get("/api/scans/nope/export/cbom").status_code == 422
