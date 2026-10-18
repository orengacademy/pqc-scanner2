"""Fleet store: host upsert, idempotent ingest, summary, history, pruning, rollup."""
import pytest
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

from pqcscan.core.bands import count_bands, readiness_score
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, ScanBundle, dump_bundle, load_bundle
from pqcscan.store.repo import Repo
from pqcscan.store.schema import ComponentRow, FindingRow, FrameworkView, GraphEdge, Host

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


def test_fleet_summary_counts_in_sql_not_per_finding(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h1 = fleet.upsert_host(WEB01); h2 = fleet.upsert_host(WEB02)
    fleet.upsert_host(HostIdentity(machine_id="m-new", hostname="new", os="linux"))     # no scan yet
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"] * 30 + ["ML-KEM-768"] * 10), h1.id)
    last = fleet.ingest_bundle(_bundle(src, WEB02, ["ECDSA-P256"] * 20), h2.id)
    statements: list[str] = []
    listener = lambda *a: statements.append(a[2])  # noqa: E731
    event.listen(fleet.engine, "before_cursor_execute", listener)
    try:
        rows = {x.host.hostname: x for x in fleet.fleet_summary()}
    finally:
        event.remove(fleet.engine, "before_cursor_execute", listener)
    assert len(statements) <= 3, statements
    assert rows["new"].scan_id is None and rows["web02"].scan_id == last.scan_id
    for x in (rows["web01"], rows["web02"]):
        found = fleet.list_findings(x.scan_id)
        assert (x.total, x.crit, x.readiness) == (len(found), len(found), readiness_score(count_bands(found)))


def test_failed_ingest_leaves_host_row_untouched(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    good = _bundle(src, WEB01, ["RSA-2048"])
    renamed = HostIdentity(machine_id="m-web01", hostname="renamed", os="linux", labels={"env": "x"})
    bad = ScanBundle(schema_version=good.schema_version, scan_uuid="u-bad", host=renamed, scan=good.scan,
                     findings=[{"title": "no probe_id"}])
    with pytest.raises(KeyError):
        fleet.ingest_bundle(bad, h.id)
    after = fleet.get_host(h.id)
    assert (after.hostname, after.labels, after.last_seen) == (h.hostname, h.labels, h.last_seen)
    ok = ScanBundle(schema_version=good.schema_version, scan_uuid="u-ok", host=renamed, scan=good.scan, findings=[])
    fleet.ingest_bundle(ok, h.id)
    assert fleet.get_host(h.id).hostname == "renamed"             # a stored bundle refreshes the host row


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
    assert sorted((r.algorithm, r.evidence["_fleet"]["host"]) for r in rows) == [("ECDSA-P256", "web02"),
                                                                                  ("RSA-2048", "web01")]
    assert fleet.get_scan(rid).label == "fleet-rollup"
    assert {r.evidence["_fleet"]["machine_id"] for r in rows} == {h1.machine_id, h2.machine_id}
    assert {r.evidence["_fleet"]["host_id"] for r in rows} == {h1.id, h2.id}
    assert all("host" not in r.evidence for r in rows)  # the scan-target key is never overwritten
    assert len(fleet.list_framework_views(rid)) == 2    # views travel with the copied findings
    fleet.delete_scan(rid)
    assert fleet.get_scan(rid) is None and fleet.list_findings(rid) == []


def test_ordering_uses_server_scan_id_not_client_started_at(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    first = _bundle(src, WEB01, ["RSA-1024"])
    last = _bundle(src, WEB01, ["RSA-2048", "ECDSA-P256"])
    first.scan["started_at"] = "2030-01-01T00:00:00"      # client claims the earlier scan is newest
    last.scan["started_at"] = "2020-01-01T00:00:00"
    fleet.ingest_bundle(first, h.id)
    r_last = fleet.ingest_bundle(last, h.id)
    assert fleet.host_history(h.id)[0].id == r_last.scan_id
    assert fleet.fleet_summary()[0].scan_id == r_last.scan_id
    assert fleet.get_scan(r_last.scan_id).started_at.year == 2020      # reported value still stored


def test_ingest_rejects_unknown_status(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    b = _bundle(src, WEB01, ["RSA-2048"])
    b.scan["status"] = "bogus"
    assert fleet.get_scan(fleet.ingest_bundle(b, h.id).scan_id).status == "done"
    b2 = _bundle(src, WEB01, [])
    b2.scan["status"] = "failed"
    assert fleet.get_scan(fleet.ingest_bundle(b2, h.id).scan_id).status == "failed"


def test_prune_rejects_keep_below_one_and_is_exact(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    with pytest.raises(ValueError):
        fleet.prune_scans(keep_per_host=0)
    ids = [fleet.ingest_bundle(_bundle(src, WEB01, []), h.id).scan_id for _ in range(5)]
    assert fleet.prune_scans(keep_per_host=2) == 3
    assert sorted(s.id for s in fleet.host_history(h.id)) == sorted(ids[-2:])


def test_prune_host_keeps_newest_n_and_leaves_other_hosts_and_rollups(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h1, h2 = fleet.upsert_host(WEB01), fleet.upsert_host(WEB02)
    ids1 = [fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h1.id).scan_id for _ in range(4)]
    ids2 = [fleet.ingest_bundle(_bundle(src, WEB02, ["RSA-2048"]), h2.id).scan_id for _ in range(3)]
    rollup = fleet.materialize_fleet_rollup()
    assert fleet.prune_host(h1.id, 2) == 2
    assert sorted(s.id for s in fleet.host_history(h1.id)) == sorted(ids1[-2:])
    assert sorted(s.id for s in fleet.host_history(h2.id)) == sorted(ids2)     # other host untouched
    assert fleet.get_scan(rollup) is not None                                  # host_id=None rollup untouched
    assert fleet.prune_host(h1.id, 2) == 0                                     # idempotent
    with pytest.raises(ValueError):
        fleet.prune_host(h1.id, 0)


def test_prune_host_never_deletes_baselined_scans(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    ids = [fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id).scan_id for _ in range(5)]
    fleet.create_baseline(scan_id=ids[0], label="golden")
    assert fleet.prune_host(h.id, 2) == 2                   # baseline kept, and it does not use up a keep slot
    assert sorted(s.id for s in fleet.host_history(h.id)) == [ids[0], ids[3], ids[4]]
    assert [b.scan_id for b in fleet.list_baselines()] == [ids[0]]


def test_prune_host_keeps_newest_done_scan_behind_failed_ones(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    good = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id).scan_id
    failed = []
    for _ in range(3):
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        src.finish_scan(sid, status="failed")
        failed.append(fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, WEB01)), h.id).scan_id)
    assert fleet.prune_host(h.id, 2) == 1                   # oldest failed scan goes; the only done scan stays
    assert sorted(s.id for s in fleet.host_history(h.id)) == [good, failed[1], failed[2]]


def test_daemon_keep_scans_per_host_minimum_is_two():
    from click.testing import CliRunner

    from pqcscan.cli.daemon_cmd import daemon_cmd
    r = CliRunner().invoke(daemon_cmd, ["--keep-scans-per-host", "1"])
    assert r.exit_code == 2 and "keep-scans-per-host" in r.output


def test_rollup_skips_views_of_drift_rows(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    sid = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id).scan_id
    fid = fleet.record_finding(sid, Finding(probe_id="fleet.drift", algorithm="N/A", classification=Classification.INFO,
                                            severity=Severity.INFO, title="drift: added x"))
    fleet.record_framework_view(fid, framework="cnsa2", clause="c", verdict="info", deadline=None)
    roll = fleet.materialize_fleet_rollup()             # no KeyError on the drift row's view
    assert len(fleet.list_framework_views(roll)) == 1


def test_keep_two_with_drift_still_stores_drift(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    ids, results = [], []
    for algs in (["RSA-2048"], ["RSA-2048", "RSA-1024"], ["RSA-1024"]):
        res = fleet.ingest_bundle(_bundle(src, WEB01, algs), h.id)
        fleet.prune_host(h.id, 2)
        ids.append(res.scan_id); results.append(res)
    assert results[2].drift == 1                            # RSA-2048 removed, against the surviving second scan
    drift = [f for f in fleet.list_findings(ids[2]) if f.probe_id == "fleet.drift"]
    assert [f.evidence["change"] for f in drift] == ["removed"]
    assert sorted(s.id for s in fleet.host_history(h.id)) == ids[1:]


def test_ingest_unknown_host_and_foreign_scan_uuid(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    ha = fleet.upsert_host(WEB01); hb = fleet.upsert_host(WEB02)
    b = _bundle(src, WEB01, ["RSA-2048"])
    with pytest.raises(ValueError, match="host 999 not found"):
        fleet.ingest_bundle(b, 999)
    assert fleet.list_scans() == []
    fleet.ingest_bundle(b, ha.id)
    with pytest.raises(ValueError, match="another host"):
        fleet.ingest_bundle(b, hb.id)
    assert len(fleet.list_scans()) == 1


def test_delete_scan_removes_components_and_edges(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    sid = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id).scan_id
    with Session(fleet.engine) as s:
        c1 = ComponentRow(scan_id=sid, purl="pkg:a", type="lib", name="a", discovered_by="t")
        c2 = ComponentRow(scan_id=sid, purl="pkg:b", type="lib", name="b", discovered_by="t")
        s.add_all([c1, c2]); s.flush()
        s.add(GraphEdge(scan_id=sid, src_id=c1.id, dst_id=c2.id, edge_type="uses"))
        s.commit()
    fleet.delete_scan(sid)
    with Session(fleet.engine) as s:
        assert s.execute(select(func.count()).select_from(ComponentRow)).scalar_one() == 0
        assert s.execute(select(func.count()).select_from(GraphEdge)).scalar_one() == 0


def test_token_hash_never_unrevokes_only_unrevoke_host_does(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    h = repo.upsert_host(WEB01, token_hash="abc")
    repo.revoke_host(h.id)
    h2 = repo.upsert_host(WEB01, token_hash="def")
    assert h2.revoked is True and repo.get_host(h.id).revoked is True
    assert repo.unrevoke_host(h.id) is True
    got = repo.get_host(h.id)
    assert got.revoked is False and got.token_hash == "def"
    assert repo.unrevoke_host(999) is False
    repo.revoke_host(h.id)
    repo.unrevoke_host(h.id)
    assert repo.get_host(h.id).token_hash is None                 # agent must re-enroll


def _age(repo: Repo, scan_id: int, hours: float = 2) -> None:
    from datetime import timedelta

    from pqcscan.store.schema import Scan
    with Session(repo.engine) as s:
        sc = s.get(Scan, scan_id)
        sc.started_at -= timedelta(hours=hours)
        s.commit()


def test_delete_stale_rollups_sweeps_temporary_only(tmp_db_path, tmp_path):
    from pqcscan.store.merge import merge_dbs
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id)
    orphan = fleet.materialize_fleet_rollup()                       # simulates a hard kill: never deleted
    merged = merge_dbs(fleet, [tmp_path / "src.db"], rollup=True).rollup_scan_id   # persistent, same label
    assert merged is not None
    assert fleet.delete_stale_rollups() == 0                        # under an hour old: may be rendering
    _age(fleet, orphan)
    _age(fleet, merged)
    assert fleet.delete_stale_rollups() == 1
    assert fleet.get_scan(orphan) is None
    assert fleet.get_scan(merged) is not None                       # merge's rollup is user data
    assert fleet.delete_stale_rollups() == 0


def test_reconcile_and_prune_sweep_orphaned_rollup(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    h = fleet.upsert_host(WEB01)
    fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048"]), h.id)
    r1 = fleet.materialize_fleet_rollup()
    _age(fleet, r1)
    fleet.reconcile_running_scans()
    assert fleet.get_scan(r1) is None
    r2 = fleet.materialize_fleet_rollup()
    fresh = fleet.materialize_fleet_rollup()                     # an export in flight
    _age(fleet, r2)
    fleet.prune_scans(keep_per_host=5)
    assert fleet.get_scan(r2) is None and fleet.get_scan(fresh) is not None


def test_ingest_stores_drift_rows_only_when_findings_change(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    first = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048", "RSA-1024"]), host.id)
    assert first.drift == 0                                   # no previous scan, nothing to compare
    second = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048", "ECDSA-P256"]), host.id)
    drift = [f for f in fleet.list_findings(second.scan_id) if f.probe_id == "fleet.drift"]
    assert second.drift == 2 and len(drift) == 2
    assert {(f.evidence["change"], f.evidence["algorithm"]) for f in drift} == {
        ("removed", "RSA-1024"), ("added", "ECDSA-P256")}
    assert all(f.severity == "info" for f in drift)
    third = fleet.ingest_bundle(_bundle(src, WEB01, ["RSA-2048", "ECDSA-P256"]), host.id)
    assert third.drift == 0
    assert not [f for f in fleet.list_findings(third.scan_id) if f.probe_id == "fleet.drift"]


def _seed_labels(repo: Repo, host_id: int, labels: dict[str, str]) -> None:
    with Session(repo.engine) as s:
        s.get(Host, host_id).labels = labels
        s.commit()


def test_merged_host_labels_stop_at_the_cap_and_never_refuse_the_scan(tmp_db_path, tmp_path):
    from loguru import logger
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01, token_hash="t")
    seen: list[str] = []
    sink = logger.add(lambda m: seen.append(str(m)), level="WARNING")
    try:
        fleet.ingest_bundle(_bundle(src, HostIdentity("m-web01", "web01", "linux", {f"a{i}": "v" for i in range(63)}),
                                    ["RSA-2048"]), host.id)
        assert len(fleet.get_host(host.id).labels) == 64 and not seen          # env + 63
        # existing keys update, three new keys are dropped (sorted order), the scan is stored
        res = fleet.ingest_bundle(_bundle(src, HostIdentity("m-web01", "web01", "linux",
                                                            {"a0": "changed", "z3": "v", "z1": "v", "z2": "v"}),
                                          ["RSA-2048"]), host.id)
        assert not res.duplicate and res.stored_findings == 1
    finally:
        logger.remove(sink)
    labels = fleet.get_host(host.id).labels
    assert len(labels) == 64 and labels["a0"] == "changed" and not {"z1", "z2", "z3"} & labels.keys()
    assert len(seen) == 1 and "web01" in seen[0] and "z1, z2, z3" in seen[0]
    assert len(fleet.host_history(host.id)) == 2


def test_host_already_over_the_cap_keeps_labels_and_still_ingests_and_enrolls(tmp_db_path, tmp_path):
    # v0.10.2 enforced the cap per bundle only, so a collector may hold hosts with more than 64 labels
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01, token_hash="t")
    _seed_labels(fleet, host.id, {f"old{i}": "v" for i in range(100)})
    incoming = HostIdentity("m-web01", "web01", "linux", {"old5": "new", "fresh": "v"})
    fleet.ingest_bundle(_bundle(src, incoming, ["RSA-2048"]), host.id)
    fleet.upsert_host(incoming)
    labels = fleet.get_host(host.id).labels
    assert len(labels) == 100 and labels["old5"] == "new" and "fresh" not in labels
    assert len(fleet.host_history(host.id)) == 1


def test_ingest_issues_a_bounded_number_of_statements(tmp_db_path, tmp_path):
    """Views must not cost a statement each: 40 findings with 5 views apiece stay near one statement per finding."""
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
    for i in range(40):
        fid = src.record_finding(sid, Finding(probe_id="fs.cert.x509", algorithm=f"RSA-{i}",
                                              classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT,
                                              title=f"t{i}"))
        for k in range(5):
            src.record_framework_view(fid, framework=f"fw{k}", clause=f"c{i}", verdict="non-compliant", deadline=None)
    src.finish_scan(sid, status="done")
    b = load_bundle(dump_bundle(src, sid, WEB01))
    n = []
    event.listen(fleet.engine, "before_cursor_execute", lambda *a: n.append(1))
    r = fleet.ingest_bundle(b, host.id)
    assert (r.stored_findings, r.stored_views) == (40, 200)
    assert len(n) <= 40 + 20
    with Session(fleet.engine) as s:     # each view is attached to its own finding, in order
        pairs = s.execute(select(FindingRow.title, func.count(FrameworkView.id)).join(
            FrameworkView, FrameworkView.finding_id == FindingRow.id).group_by(FindingRow.id)).all()
    assert len(pairs) == 40 and all(c == 5 for _, c in pairs)


# --- bulk ingest path: no RETURNING, batch boundaries, empty and drift-only bundles -------------------------------

def _doc_bundle(host: HostIdentity, n: int, *, views: int = 1, uuid: str | None = None) -> ScanBundle:
    """A bundle built straight from a document (no source Repo), n findings with `views` views each."""
    import gzip
    import json
    import uuid as uuid_mod
    doc = {"schema_version": 1, "scan_uuid": uuid or str(uuid_mod.uuid4()),
           "host": {"machine_id": host.machine_id, "hostname": host.hostname, "os": host.os, "labels": host.labels,
                    "agent_version": ""},
           "scan": {"started_at": "2026-10-17T00:00:00+00:00", "finished_at": "2026-10-17T00:01:00+00:00",
                    "mode": "user", "status": "done", "probe_versions": {}, "tool_versions": {}},
           "findings": [{"probe_id": "fs.cert.x509", "algorithm": f"RSA-{i}", "classification": "tinggi",
                         "severity": "high", "title": f"f{i}", "evidence": {"path": f"/p/{i}"}, "remediation": {},
                         "created_at": "2026-10-17T00:00:30+00:00",
                         "views": [{"framework": f"fw{k}", "clause": f"c{i}", "verdict": "at-risk", "deadline": None}
                                   for k in range(views)]} for i in range(n)]}
    return load_bundle(gzip.compress(json.dumps(doc).encode()))


def _no_returning(repo: Repo) -> None:
    """What SQLite < 3.35 looks like to SQLAlchemy (its dialect clears these three): no RETURNING. Multi-row
    INSERT ... VALUES pages still apply, they need only SQLite 3.7.11."""
    d = repo.engine.dialect
    d.insert_returning = d.update_returning = d.delete_returning = False


def test_bulk_ingest_works_without_returning(tmp_db_path):
    fleet = Repo(tmp_db_path); fleet.init_schema()
    _no_returning(fleet)
    host = fleet.upsert_host(WEB01)
    b = _doc_bundle(WEB01, 40, views=3)
    r = fleet.ingest_bundle(b, host.id)
    assert (r.stored_findings, r.stored_views, r.duplicate) == (40, 120, False)
    scan = fleet.get_scan(r.scan_id)
    assert scan.host_id == host.id and scan.scan_uuid == b.scan_uuid
    views = {(f.title, v.clause) for f in fleet.list_findings(r.scan_id) for v in fleet.list_framework_views(r.scan_id)
             if v.finding_id == f.id}
    assert views == {(f"f{i}", f"c{i}") for i in range(40)}      # every view sits on its own finding


def test_bulk_ingest_across_the_batch_boundary(tmp_db_path):
    """2,500 findings is past SQLAlchemy's 1,000-row insert batch; views must still land on the right finding.

    Findings and views go as multi-row INSERT ... VALUES pages, never executemany: sqlite3 steps an executemany row
    by row and psycopg 3 pipelines one Execute per row (benchmark/fleet/profiles/*-before)."""
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    rows_per_statement: list[int] = []

    @event.listens_for(fleet.engine, "before_cursor_execute")
    def _note(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith(("INSERT INTO findings", "INSERT INTO framework_views")):
            rows_per_statement.append(statement.count("), (") + 1)
    r = fleet.ingest_bundle(_doc_bundle(WEB01, 2500, views=2), host.id)
    assert (r.stored_findings, r.stored_views) == (2500, 5000)
    assert sum(rows_per_statement) == 7500 and len(rows_per_statement) <= 10, rows_per_statement
    with Session(fleet.engine) as s:
        pairs = s.execute(select(FindingRow.title, FrameworkView.clause).join(
            FrameworkView, FrameworkView.finding_id == FindingRow.id).where(FindingRow.scan_id == r.scan_id)).all()
    assert len(pairs) == 5000 and all(t == "f" + c[1:] for t, c in pairs)


def test_bulk_ingest_round_trips_json_dates_and_deadlines(tmp_db_path):
    """The Core INSERT binds evidence/remediation (JSON), created_at and a view deadline like the ORM did."""
    from datetime import date, datetime
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    b = _doc_bundle(WEB01, 2, views=1)
    b.findings[0]["remediation"] = {"steps": ["rotate", "re-issue"]}
    b.findings[0]["views"][0]["deadline"] = "2030-12-31"
    r = fleet.ingest_bundle(b, host.id)
    f = {x.title: x for x in fleet.list_findings(r.scan_id)}
    assert f["f0"].evidence == {"path": "/p/0"} and f["f0"].remediation == {"steps": ["rotate", "re-issue"]}
    assert f["f0"].created_at == datetime(2026, 10, 17, 0, 0, 30)
    deadlines = {v.finding_id: v.deadline for v in fleet.list_framework_views(r.scan_id)}
    assert deadlines == {f["f0"].id: date(2030, 12, 31), f["f1"].id: None}


def test_empty_bundle_and_drift_only_bundle(tmp_db_path):
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    empty = fleet.ingest_bundle(_doc_bundle(WEB01, 0), host.id)
    assert (empty.stored_findings, empty.stored_views, empty.duplicate, empty.drift) == (0, 0, False, 0)
    fleet.ingest_bundle(_doc_bundle(WEB01, 3), host.id)
    gone = fleet.ingest_bundle(_doc_bundle(WEB01, 0), host.id)       # everything removed: only drift rows are stored
    assert (gone.stored_findings, gone.stored_views, gone.drift) == (0, 0, 3)
    rows = fleet.list_findings(gone.scan_id)
    assert len(rows) == 3 and {f.probe_id for f in rows} == {"fleet.drift"}
    assert {f.evidence["change"] for f in rows} == {"removed"}


def test_bulk_ingest_keeps_identity_fleet_namespace_and_retention(tmp_db_path):
    fleet = Repo(tmp_db_path); fleet.init_schema()
    host = fleet.upsert_host(WEB01)
    ids = [fleet.ingest_bundle(_doc_bundle(WEB01, 5, views=2), host.id).scan_id for _ in range(3)]
    assert all(fleet.get_scan(i).host_id == host.id for i in ids)
    assert fleet.prune_host(host.id, 2) == 1
    assert fleet.get_scan(ids[0]) is None and fleet.get_scan(ids[2]) is not None
    rollup = fleet.materialize_fleet_rollup()
    rows = fleet.list_findings(rollup)
    assert len(rows) == 5 and {r.evidence["_fleet"]["machine_id"] for r in rows} == {WEB01.machine_id}
