"""benchmark/fleet/reconcile.py: fleet CBOM / fleet JSON vs asset inventory."""
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pqcscan.cbom.builder import build_cbom
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.bundle import HostIdentity, dump_bundle, load_bundle
from pqcscan.store.repo import Repo

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmark" / "fleet"))
import reconcile as rc

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
FRESH = "2026-10-17T08:00:00+00:00"
OLD = "2026-10-14T08:00:00+00:00"

# (machine_id, hostname, TLS finding titles) as the fleet reports them.
REPORTING = [
    ("m-web01", "web01", ["TLSv1.3 negotiated cipher TLS_AES_256_GCM_SHA384"]),
    ("m-web02", "web02", ["TLSv1.0 negotiated cipher AES128-SHA", "TLSv1.2 negotiated cipher ECDHE-RSA-AES256-GCM"]),
    ("m-db01", "db01", ["TLSv1.2 negotiated cipher ECDHE-RSA-AES256-GCM"]),
    ("m-app01", "app01", []),
    ("m-rogue", "rogue01", []),
    ("m-web03", "web99", []),            # inventory knows this machine_id as web03
    ("m-other", "web04", []),            # inventory knows web04 with a different machine_id
    ("m-cache", "cache01", []),          # inventory says cache01.corp.example
]

INVENTORY_CSV = """hostname,machine_id,owner,environment,expected_tls_min,expected_cert_cn
WEB01,m-web01,alice,prod,TLSv1.2,web01.corp
web02,m-web02,bob,prod,TLS 1.2,web02.corp
db01,,carol,prod,1.2,
app01,m-app01,dave,prod,,
web03,m-web03,erin,dr,,
web04,m-web04,frank,dr,,
cache01.corp.example,,gina,prod,,
batch01,m-batch,hal,prod,,
"""


def _fleet_json(path: Path) -> Path:
    hosts = [{"host_id": i, "machine_id": mid, "hostname": name, "os": "linux", "labels": {},
              "first_seen": OLD, "last_seen": OLD if name == "db01" else FRESH, "revoked": name == "app01"}
             for i, (mid, name, _) in enumerate(REPORTING, start=1)]
    path.write_text(json.dumps(hosts))
    return path


def _real_cbom(tmp_path: Path) -> dict:
    """A fleet CBOM produced by the real Repo + materialize_fleet_rollup + build_cbom path."""
    src = Repo(tmp_path / "src.db"); src.init_schema()
    fleet = Repo(tmp_path / "fleet.db"); fleet.init_schema()
    for mid, name, titles in REPORTING:
        ident = HostIdentity(machine_id=mid, hostname=name, os="linux", labels={})
        sid = src.create_scan(mode="user", probe_versions={}, tool_versions={})
        for t in titles:
            src.record_finding(sid, Finding(probe_id="net.tls.handshake", algorithm="AES-128",
                                            classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT,
                                            title=t, evidence={"endpoint": f"{name}:443"}))
        src.finish_scan(sid, status="done")
        host = fleet.upsert_host(ident)
        fleet.ingest_bundle(load_bundle(dump_bundle(src, sid, ident)), host.id)
    return build_cbom(fleet, fleet.materialize_fleet_rollup())


def _with_cert_cns(cbom: dict) -> dict:
    """The exported CBOM has no cert subject today; add the property the script reads."""
    for mid, name, cn in (("m-web01", "web01", "web01.corp"), ("m-web02", "web02", "old.corp")):
        cbom["components"].append({
            "type": "cryptographic-asset", "name": "RSA-2048", "description": "server cert uses RSA-2048",
            "properties": [{"name": "pqcscan:probe", "value": "net.tls.handshake"},
                           {"name": "pqcscan:host", "value": name}, {"name": "pqcscan:machine_id", "value": mid},
                           {"name": "pqcscan:cert_subject", "value": f"CN={cn},O=Corp"}]})
    return cbom


@pytest.fixture
def inputs(tmp_path):
    cbom = tmp_path / "fleet.cbom.json"
    cbom.write_text(json.dumps(_with_cert_cns(_real_cbom(tmp_path))))
    inv = tmp_path / "inventory.csv"
    inv.write_text(INVENTORY_CSV)
    return {"cbom": cbom, "fleet": _fleet_json(tmp_path / "fleet.json"), "inv": inv, "out": tmp_path / "out"}


def _run(i, *, cbom=True, fleet=True, inv=None) -> tuple[int, list[dict]]:
    argv = ["--inventory", str(inv or i["inv"]), "--out-dir", str(i["out"])]
    if cbom:
        argv += ["--cbom", str(i["cbom"])]
    if fleet:
        argv += ["--fleet", str(i["fleet"])]
    code = rc.main(argv, now=NOW)
    out = i["out"] / "discrepancies.csv"
    return code, list(csv.DictReader(out.open())) if out.exists() else []


def _by_class(rows):
    got: dict[str, list[str]] = {}
    for r in rows:
        got.setdefault(r["class"], []).append(r["host"])
    return got


def test_every_class_is_reported(inputs):
    code, rows = _run(inputs)
    assert code == 1
    assert _by_class(rows) == {
        "missing_from_fleet": ["batch01"],
        "unknown_to_inventory": ["rogue01"],
        "identity_mismatch": ["web03", "web04"],
        "weak_match": ["cache01.corp.example"],
        "stale": ["db01"],
        "revoked": ["app01"],
        "tls_below_expected": ["web02"],
        "cert_cn_mismatch": ["web02"],
    }
    assert {r["suggested_action"] for r in rows} != {""}
    tls = next(r for r in rows if r["class"] == "tls_below_expected")
    assert "TLSv1.0" in tls["detail"] and "TLSv1.2" in tls["detail"]
    assert "old.corp" in next(r for r in rows if r["class"] == "cert_cn_mismatch")["detail"]


def test_identity_mismatch_covers_both_directions(inputs):
    _, rows = _run(inputs)
    details = {r["host"]: r["detail"] for r in rows if r["class"] == "identity_mismatch"}
    assert "web99" in details["web03"] and "m-web03" in details["web03"]    # same machine_id, other hostname
    assert "m-web04" in details["web04"] and "m-other" in details["web04"]  # same hostname, other machine_id


def test_markdown_has_counts_before_table(inputs):
    _run(inputs)
    md = (inputs["out"] / "discrepancies.md").read_text()
    assert md.index("## Summary: 9 discrepancies") < md.index("| missing_from_fleet | 1 |") < md.index("## Discrepancies")
    assert all(f"| {c} |" in md for c in rc.CLASSES)
    assert "| tls_below_expected | web02 |" in md


def test_clean_run_exits_zero(inputs, tmp_path):
    inv = tmp_path / "clean.csv"
    inv.write_text("hostname,machine_id,expected_tls_min\nweb01,m-web01,TLSv1.2\n")
    fleet = tmp_path / "one.json"
    fleet.write_text(json.dumps({"hosts": [{"hostname": "web01", "machine_id": "m-web01", "last_seen": FRESH,
                                            "revoked": False}]}))
    code, rows = _run({**inputs, "fleet": fleet}, cbom=False, inv=inv)
    assert (code, rows) == (0, [])
    assert "None." in (inputs["out"] / "discrepancies.md").read_text()


def test_weak_match_is_flagged_not_silent_and_still_checked(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname,expected_tls_min\nweb01.corp.example,TLSv1.2\nweb02,TLSv1.2\n")
    fleet = tmp_path / "f.json"
    fleet.write_text(json.dumps([{"hostname": "web01", "machine_id": "a", "last_seen": OLD},
                                 {"hostname": "web02.other.example", "machine_id": "b", "last_seen": FRESH}]))
    code, rows = _run({"inv": inv, "fleet": fleet, "out": tmp_path / "o"}, cbom=False)
    got = _by_class(rows)
    assert code == 1 and got["weak_match"] == ["web01.corp.example", "web02"]
    assert got["stale"] == ["web01"] and "unknown_to_inventory" not in got   # weak match still gets the other checks


def test_two_fqdns_with_different_domains_are_not_a_match(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname\nweb01.a.example\n")
    fleet = tmp_path / "f.json"
    fleet.write_text(json.dumps([{"hostname": "web01.b.example", "machine_id": "x", "last_seen": FRESH}]))
    _, rows = _run({"inv": inv, "fleet": fleet, "out": tmp_path / "o"}, cbom=False)
    assert _by_class(rows) == {"missing_from_fleet": ["web01.a.example"], "unknown_to_inventory": ["web01.b.example"]}


def test_real_cbom_alone_yields_tls_but_states_what_it_cannot_check(tmp_path):
    cbom = tmp_path / "c.cbom.json"
    cbom.write_text(json.dumps(_real_cbom(tmp_path)))     # exactly what build_cbom emits: no cert subject
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname,machine_id,expected_tls_min,expected_cert_cn\nweb02,m-web02,TLSv1.2,web02.corp\n")
    code, rows = _run({"cbom": cbom, "inv": inv, "out": tmp_path / "o"}, fleet=False)
    got = _by_class(rows)
    assert got["tls_below_expected"] == ["web02"] and "cert_cn_mismatch" not in got
    md = (tmp_path / "o" / "discrepancies.md").read_text()
    assert "## Not assessed" in md and "no certificate subject" in md and "Pass --fleet" in md
    assert code == 1


@pytest.mark.parametrize("raw, want", [("TLSv1.2", "TLSv1.2"), ("tls 1.3", "TLSv1.3"), ("1.1", "TLSv1.1"),
                                       ("TLSv1", "TLSv1.0"), ("SSLv3", "SSLv3"), ("TLS1.2", "TLSv1.2"),
                                       ("1.4", None), ("tls", None), ("modern", None)])
def test_norm_tls(raw, want):
    assert rc.norm_tls(raw) == want


def test_spreadsheet_formulas_and_pipes_are_neutralised(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname\nok01\n")
    fleet = tmp_path / "f.json"
    fleet.write_text(json.dumps([{"hostname": "=HYPERLINK(\"http://x\")|evil", "machine_id": "x", "last_seen": FRESH}]))
    _, rows = _run({"inv": inv, "fleet": fleet, "out": tmp_path / "o"}, cbom=False)
    assert next(r for r in rows if r["class"] == "unknown_to_inventory")["host"].startswith("'=HYPERLINK")
    assert "\\|evil" in (tmp_path / "o" / "discrepancies.md").read_text()


def test_fleet_summary_cli_shape_loads(tmp_path):
    """`pqcscan fleet summary --json` has finished_at, no machine_id/last_seen/revoked."""
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname\nweb01\n")
    fleet = tmp_path / "f.json"
    fleet.write_text(json.dumps([{"host_id": 1, "hostname": "web01", "labels": {}, "scan_id": 3,
                                  "finished_at": OLD, "readiness": 40, "crit": 1, "high": 0, "total": 1, "drift": 0}]))
    _, rows = _run({"inv": inv, "fleet": fleet, "out": tmp_path / "o"}, cbom=False)
    assert _by_class(rows) == {"stale": ["web01"]}


@pytest.mark.parametrize("case", ["missing_inventory", "no_hostname_column", "bad_tls", "bad_fleet_json",
                                  "bad_cbom", "empty_hostname", "empty_inventory"])
def test_bad_input_exits_two(inputs, tmp_path, case, capsys):
    inv, fleet, cbom = inputs["inv"], inputs["fleet"], inputs["cbom"]
    bad = tmp_path / "bad"
    if case == "missing_inventory":
        inv = tmp_path / "nope.csv"
    elif case == "no_hostname_column":
        inv = tmp_path / "x.csv"; inv.write_text("host,owner\nweb01,a\n")
    elif case == "bad_tls":
        inv = tmp_path / "x.csv"; inv.write_text("hostname,expected_tls_min\nweb01,modern\n")
    elif case == "empty_hostname":
        inv = tmp_path / "x.csv"; inv.write_text("hostname,owner\n,a\n")
    elif case == "empty_inventory":
        inv = tmp_path / "x.csv"; inv.write_text("hostname,owner\n")
    elif case == "bad_fleet_json":
        bad.write_text("{not json"); fleet = bad
    elif case == "bad_cbom":
        bad.write_text(json.dumps({"bomFormat": "CycloneDX"})); cbom = bad
    code = rc.main(["--inventory", str(inv), "--fleet", str(fleet), "--cbom", str(cbom),
                    "--out-dir", str(inputs["out"])], now=NOW)
    assert code == 2 and "reconcile:" in capsys.readouterr().err
    assert not (inputs["out"] / "discrepancies.csv").exists()


def test_no_source_given_exits_two(inputs):
    with pytest.raises(SystemExit) as e:
        rc.main(["--inventory", str(inputs["inv"])], now=NOW)
    assert e.value.code == 2
