"""The SIMULATED soak harness end to end at toy size: 3 hosts, 2 cycles, 5 s interval, SQLite, no faults.

Proves the wiring (real `pqcscan agent --once` per host against a real collector), not the fault plan."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import soak

pytestmark = pytest.mark.benchmark


def test_three_hosts_two_cycles_sqlite():
    r = soak.run(db="sqlite", hosts=3, cycles=2, interval=5, faults=False, workers=3, keep=3, record=False,
                 command="smoke")
    last = r["cycles"][-1]
    assert last["totals"]["scans"] == 6, last["totals"]          # 3 hosts x 2 cycles stored
    assert last["totals"]["spool"] == 0 and last["totals"]["rc"] == 0
    assert r["anomalies"] == []
    assert r["final"]["hosts_in_fleet"] == 3


def test_observe_never_writes_to_the_collector_db(tmp_path, monkeypatch):
    """`--observe` points at a live collector's DB: a DB from an older schema must come out byte for byte unchanged."""
    import sqlite3

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(
        "create table hosts (id integer primary key, machine_id text, labels text, last_seen text);"
        "create table scans (id integer primary key, host_id integer);"          # no scan_uuid: an older schema
        "create table findings (id integer primary key, scan_id integer, probe_id text, title text);"
        "insert into hosts values (1, 'm1', '{\"a\": \"b\"}', '2026-01-01');"
        "insert into scans values (1, 1);"
    )
    con.commit()
    con.close()
    before = db.read_bytes()
    monkeypatch.setattr(soak, "RESULTS", tmp_path / "results")
    r = soak.observe(target=str(db), access_log=None, cycles=1, interval=0)
    assert r["cycles"][0]["hosts_enrolled"] == 1
    assert db.read_bytes() == before                                    # no migration, no WAL switch, no write
    cols = [c[1] for c in sqlite3.connect(db).execute("pragma table_info(scans)")]
    assert "scan_uuid" not in cols
