from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.daemon.app import create_app
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo
from pqcscan.store.schema import Host
from pqcscan.util.clock import utcnow


def _seed(db, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(db); fleet.init_schema()
    for name, env in (("web01", "prod"), ("dr01", "dr")):
        h = fleet.upsert_host(HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux", labels={"env": env}))
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        src.record_finding(sid, Finding(probe_id="p", algorithm="RSA-2048", classification=Classification.SANGAT_TINGGI,
                                        severity=Severity.CRIT, title=f"{name} weak"))
        src.finish_scan(sid, status="done")
        fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, HostIdentity(machine_id=f"m-{name}", hostname=name, os="linux"))), h.id)
    return fleet


def _client(db, registry):
    return TestClient(create_app(db_path=db, registry=registry), base_url="http://127.0.0.1")


def test_fleet_page_lists_hosts_and_filters(tmp_db_path, fast_registry, tmp_path):
    _seed(tmp_db_path, tmp_path)
    c = _client(tmp_db_path, fast_registry)
    r = c.get("/fleet")
    assert r.status_code == 200 and "web01" in r.text and "dr01" in r.text
    r = c.get("/fleet?label=env=dr")
    assert "dr01" in r.text and "web01" not in r.text
    assert 'href="/fleet"' in c.get("/").text                   # nav entry
    assert "Armada" in c.get("/fleet", cookies={"pqcscan_locale": "ms"}).text


def test_fleet_host_page_and_stale_flag(tmp_db_path, fast_registry, tmp_path):
    fleet = _seed(tmp_db_path, tmp_path)
    c = _client(tmp_db_path, fast_registry)
    assert "stale" not in c.get("/fleet").text.lower()          # freshly seen hosts are not flagged
    with Session(fleet.engine) as s:
        h = s.execute(select(Host).where(Host.hostname == "dr01")).scalar_one()
        h.last_seen = utcnow() - timedelta(days=5); s.commit()
    r = c.get("/fleet")
    assert r.text.lower().count("stale") == 1                   # only dr01
    r = c.get("/fleet/1")
    assert r.status_code == 200 and "web01" in r.text and "/scans/" in r.text
    assert c.get("/fleet/99").status_code == 404


def test_fleet_label_filter_is_validated_and_escaped(tmp_db_path, fast_registry, tmp_path):
    _seed(tmp_db_path, tmp_path)
    c = _client(tmp_db_path, fast_registry)
    for bad in ("env", "a=b=c"):
        assert c.get("/fleet", params={"label": bad}).status_code == 400, bad
    assert c.get("/fleet", params={"label": ""}).status_code == 200      # empty = no filter
    r = c.get("/fleet", params={"label": '"><script>alert(1)</script>=v'})
    assert r.status_code == 200 and "<script>alert(1)" not in r.text
    assert "&lt;script&gt;" in r.text


def test_fleet_pages_escape_host_data_and_show_empty_state(tmp_db_path, fast_registry, tmp_path):
    fleet = Repo(tmp_db_path); fleet.init_schema()
    c = _client(tmp_db_path, fast_registry)
    assert "No enrolled hosts yet" in c.get("/fleet").text
    fleet.upsert_host(HostIdentity(machine_id="m-x", hostname="<b>evil</b>", os="linux", labels={"k": "<i>v</i>"}))
    for path in ("/fleet", "/fleet/1"):
        body = c.get(path).text
        assert "<b>evil</b>" not in body and "<i>v</i>" not in body, path
        assert "&lt;b&gt;evil&lt;/b&gt;" in body, path
