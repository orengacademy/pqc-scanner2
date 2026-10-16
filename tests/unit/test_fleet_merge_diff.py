"""pqcscan merge (fleet rollup) + pqcscan diff (parity gate)."""
from pathlib import Path

from click.testing import CliRunner

from pqcscan.cli.fleet import diff_cmd, merge_cmd
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.merge import ROLLUP_LABEL, merge_dbs
from pqcscan.store.repo import Repo


def _host_db(path: Path, host: str, algs: list[str]) -> int:
    r = Repo(path); r.init_schema()
    sid = r.create_scan(mode="user", probe_versions={}, tool_versions={}, host_fingerprint=host)
    for a in algs:
        fid = r.record_finding(sid, Finding(
            probe_id="fs.cert.x509", algorithm=a, classification=Classification.SANGAT_TINGGI,
            severity=Severity.CRIT, title=f"{a} cert", evidence={"path": "/etc/x.pem"},
        ))
        r.record_framework_view(fid, framework="cnsa2", clause="CNSA2:RSA", verdict="non-compliant", deadline=None)
    r.finish_scan(sid, status="done")
    return sid


def test_merge_copies_scans_and_builds_rollup(tmp_path: Path):
    a = tmp_path / "web01.db"; b = tmp_path / "web02.db"
    _host_db(a, "web01", ["RSA-2048", "RSA-1024"])
    _host_db(b, "", ["RSA-2048"])  # no fingerprint → file stem becomes the host
    fleet = Repo(tmp_path / "fleet.db"); fleet.init_schema()
    rep = merge_dbs(fleet, [a, b])
    assert (rep.sources, rep.scans_copied, rep.findings_copied) == (2, 2, 3)
    assert rep.rollup_hosts == ["web01", "web02"]
    roll = fleet.get_scan(rep.rollup_scan_id)
    assert roll is not None and roll.label == ROLLUP_LABEL and roll.status == "done"
    rows = fleet.list_findings(rep.rollup_scan_id)
    assert sorted(r.evidence["host"] for r in rows) == ["web01", "web01", "web02"]
    # framework views travel with the findings
    assert {v.framework for v in fleet.list_framework_views(rep.rollup_scan_id)} == {"cnsa2"}
    # per-host scans are still there for drill-down
    hosts = {s.host_fingerprint for s in fleet.list_scans()}
    assert {"web01", "web02", "fleet"} <= hosts


def test_merge_and_diff_cli(tmp_path: Path):
    a = tmp_path / "primary.db"; b = tmp_path / "dr.db"
    _host_db(a, "primary", ["RSA-2048"])
    _host_db(b, "dr", ["RSA-2048", "RSA-1024"])  # DR drifted
    out = tmp_path / "fleet.db"
    r = CliRunner().invoke(merge_cmd, ["-o", str(out), str(a), str(b), "--no-rollup"])
    assert r.exit_code == 0, r.output
    scans = {s.host_fingerprint: s.id for s in Repo(out).list_scans()}
    r = CliRunner().invoke(diff_cmd, ["--db", str(out), "--scan", str(scans["dr"]),
                                      "--baseline-scan", str(scans["primary"]), "--fail-on-drift"])
    assert r.exit_code == 1 and "+1 added" in r.output and "RSA-1024" in r.output
    r = CliRunner().invoke(diff_cmd, ["--db", str(out), "--scan", str(scans["primary"]),
                                      "--baseline-scan", str(scans["primary"]), "--fail-on-drift", "--json"])
    assert r.exit_code == 0 and '"drift": false' in r.output
    assert CliRunner().invoke(diff_cmd, ["--db", str(out), "--scan", "99", "--baseline-scan", "1"]).exit_code == 3
