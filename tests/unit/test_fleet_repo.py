"""Fleet store: host upsert, idempotent ingest, summary, history, pruning, rollup."""
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, ScanBundle, dump_bundle, load_bundle
from pqcscan.store.repo import Repo

WEB01 = HostIdentity(machine_id="m-web01", hostname="web01", os="linux", labels={"env": "prod"})
WEB02 = HostIdentity(machine_id="m-web02", hostname="web02", os="linux", labels={"env": "dr"})


def _bundle(src: Repo, host: HostIdentity, algs: list[str], *, uuid: str | None = None) -> ScanBundle:
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={}, scan_uuid=uuid)
    for a in algs:
        fid = src.record_finding(sid, Finding(
            probe_id="fs.cert.x509", algorithm=a, classification=Classification.SANGAT_TINGGI,
            severity=Severity.CRIT, title=f"{a} cert"))
        src.record_framework_view(fid, framework="cnsa2", clause="c", verdict="non-compliant", deadline=None)
    src.finish_scan(sid, status="done")
    return load_bundle(dump_bundle(src, sid, host))


def test_upsert_host_inserts_then_updates(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    h1 = repo.upsert_host(WEB01, token_hash="abc")
    h2 = repo.upsert_host(HostIdentity(machine_id="m-web01", hostname="web01.new", os="linux",
                                       labels={"env": "prod", "tier": "1"}, agent_version="0.10.0"))
    assert h1.id == h2.id and h2.hostname == "web01.new" and h2.labels["tier"] == "1"
    assert repo.get_host_by_token_hash("abc").id == h1.id        # token kept when not re-given
    assert repo.get_host_by_machine_id("m-web01").id == h1.id
    assert repo.revoke_host(h1.id) is True and repo.get_host(h1.id).revoked is True


def test_ingest_is_single_transaction_and_idempotent(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    b = _bundle(src, WEB01, ["RSA-2048", "RSA-1024"])
    r1 = fleet.ingest_bundle(b, host.id)
    assert (r1.stored_findings, r1.stored_views, r1.duplicate) == (2, 2, False)
    scan = fleet.get_scan(r1.scan_id)
    assert scan.host_id == host.id and scan.scan_uuid == b.scan_uuid and scan.status == "done"
    assert {v.framework for v in fleet.list_framework_views(r1.scan_id)} == {"cnsa2"}
    r2 = fleet.ingest_bundle(b, host.id)
    assert r2.duplicate is True and r2.scan_id == r1.scan_id
    assert len(fleet.list_scans()) == 1


def test_fleet_summary_latest_done_scan_per_host(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h1 = fleet.upsert_host(WEB01); h2 = fleet.upsert_host(WEB02)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-1024"]), h1.id)
    latest = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048", "ECDSA-P256"]), h1.id)
    fleet.ingest_bundle(_bundle(src, WEB02, []), h2.id)
    rows = {s.host.hostname: s for s in fleet.fleet_summary()}
    assert rows["web01"].scan_id == latest.scan_id and rows["web01"].crit == 2 and rows["web01"].total == 2
    assert rows["web02"].total == 0 and rows["web02"].readiness == 100
    assert fleet.host_history(h1.id)[0].id == latest.scan_id   # newest first


def test_prune_keeps_n_per_host(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    ids = [fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id).scan_id for _ in range(5)]
    assert fleet.prune_scans(keep_per_host=2) == 3
    left = [s.id for s in fleet.host_history(h.id)]
    assert sorted(left) == sorted(ids[-2:])
    assert fleet.list_findings(ids[0]) == []                   # findings gone with the scan


def test_materialize_fleet_rollup_unions_latest_per_host(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    assert fleet.materialize_fleet_rollup() is None
    h1 = fleet.upsert_host(WEB01); h2 = fleet.upsert_host(WEB02)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-1024"]), h1.id)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h1.id)      # latest for web01
    fleet.ingest_bundle(_bundle(src, WEB02, ["ECDSA-P256"]), h2.id)
    rid = fleet.materialize_fleet_rollup()
    rows = fleet.list_findings(rid)
    assert sorted((r.algorithm, r.evidence["host"]) for r in rows) == [("ECDSA-P256", "web02"), ("RSA-2048", "web01")]
    assert fleet.get_scan(rid).label == "fleet-rollup"
    fleet.delete_scan(rid)
    assert fleet.get_scan(rid) is None and fleet.list_findings(rid) == []
