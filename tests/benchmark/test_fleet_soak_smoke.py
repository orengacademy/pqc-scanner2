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
