from pqcscan.core.parity import drift_rows, parity_key
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo


def test_parity_key_strips_endpoints():
    k1 = parity_key("net.tls.https", "RSA-2048", "server at 10.0.0.1:443 offers RSA-2048", {"endpoint": "10.0.0.1:443"})
    k2 = parity_key("net.tls.https", "RSA-2048", "server at 10.0.0.2:443 offers RSA-2048", {"endpoint": "10.0.0.2:443"})
    assert k1 == k2 and ":443" in k1[2]
    assert parity_key("ot.modbus.tcp", "plain-Modbus", "plain Modbus/TCP at plc-a:502", {}) == \
        parity_key("ot.modbus.tcp", "plain-Modbus", "plain Modbus/TCP at [fe80::1]:502", {})
    assert parity_key("fs.cert.x509", "RSA-2048", "cert /etc/ssl/a.pem", {"path": "/etc/ssl/a.pem"}) != \
        parity_key("fs.cert.x509", "RSA-2048", "cert /etc/ssl/b.pem", {"path": "/etc/ssl/b.pem"})


def test_parity_key_host_literals_and_server_attribution():
    # evidence["host"] is the scan target; bare IPv4/IPv6 literals and the host name drop out of titles
    a = parity_key("net.ssh", "ssh-rsa", "web01 offers ssh-rsa on 10.1.2.3", {"host": "web01", "_fleet": {"hosts": 1}})
    b = parity_key("net.ssh", "ssh-rsa", "web02 offers ssh-rsa on fe80::2", {"host": "web02"})
    assert a == b
    # same port on one endpoint stays distinct from another port
    assert parity_key("net.tls.https", "RSA-2048", "weak", {"endpoint": "h:443"}) != \
        parity_key("net.tls.https", "RSA-2048", "weak", {"endpoint": "h:8443"})


def _f(alg, title, probe="fs.cert.x509"):
    return Finding(probe_id=probe, algorithm=alg, classification=Classification.TINGGI,
                   severity=Severity.HIGH, title=title)


def test_drift_rows_added_and_removed(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    a = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    b = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(a, _f("RSA-2048", "x")); repo.record_finding(a, _f("RSA-1024", "y"))
    repo.record_finding(b, _f("RSA-2048", "x")); repo.record_finding(b, _f("ECDSA-P256", "z"))
    rows = drift_rows(repo.list_findings(a), repo.list_findings(b))
    changes = sorted((r.evidence["change"], r.evidence["algorithm"]) for r in rows)
    assert changes == [("added", "ECDSA-P256"), ("removed", "RSA-1024")]
    assert all(r.probe_id == "fleet.drift" and r.classification is Classification.INFO for r in rows)


def test_drift_rows_ignore_prior_drift(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    a = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    b = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(a, _f("RSA-2048", "x")); repo.record_finding(b, _f("RSA-2048", "x"))
    repo.record_finding(a, _f("RSA-1024", "old", probe="fleet.drift"))
    assert drift_rows(repo.list_findings(a), repo.list_findings(b)) == []


def test_ingest_emits_drift_against_previous_scan(tmp_db_path, tmp_path):
    src = Repo(tmp_path / "s.db"); src.init_schema()
    fleet = Repo(tmp_db_path); fleet.init_schema()
    ident = HostIdentity(machine_id="m", hostname="h", os="linux")
    h = fleet.upsert_host(ident)
    for algs in (["RSA-2048"], ["RSA-2048", "RSA-1024"]):
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        for a in algs:
            src.record_finding(sid, _f(a, f"cert {a}"))
        src.finish_scan(sid, status="done")
        res = fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), h.id)
    drift = [r for r in fleet.list_findings(res.scan_id) if r.probe_id == "fleet.drift"]
    assert len(drift) == 1 and drift[0].evidence["change"] == "added" and drift[0].evidence["algorithm"] == "RSA-1024"
    d = fleet.diff_findings(current_scan_id=res.scan_id, baseline_scan_id=res.scan_id - 1, parity=True)
    assert len(d["added"]) == 1          # drift rows themselves are excluded from parity diffs


def test_diff_cli_parity_ignores_host_names(tmp_db_path):
    from click.testing import CliRunner

    from pqcscan.cli.fleet import diff_cmd
    repo = Repo(tmp_db_path); repo.init_schema()
    ids = []
    for host in ("10.0.0.1", "10.0.0.2"):
        sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
        repo.record_finding(sid, Finding(probe_id="net.tls.https", algorithm="RSA-2048",
                                         classification=Classification.TINGGI, severity=Severity.HIGH,
                                         title=f"server at {host}:443 offers RSA-2048",
                                         evidence={"host": host, "endpoint": f"{host}:443"}))
        ids.append(sid)
    args = ["--db", str(tmp_db_path), "--scan", str(ids[1]), "--baseline-scan", str(ids[0]), "--fail-on-drift"]
    assert CliRunner().invoke(diff_cmd, args).exit_code == 1
    assert CliRunner().invoke(diff_cmd, [*args, "--parity"]).exit_code == 0
