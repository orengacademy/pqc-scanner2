"""The fleet load harness end to end at toy size: 5 hosts, 10 s, SQLite. Proves the wiring, not the capacity."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import run_load

pytestmark = pytest.mark.benchmark


def test_five_hosts_ten_seconds_sqlite():
    r = run_load.run(db="sqlite", hosts=5, spawn_rate=5, duration_s=10, findings=50, stagger=False, record=False,
                     command="smoke")
    assert r["errors"] == 0, r["failure_samples"]
    assert r["requests"] == 5 and r["enroll_requests"] == 5      # one host, one bundle: interval is 60 s
    assert r["http_429"] == 0 and r["http_503"] == 0
    assert r["stored_hosts"] == 5 and r["stored_scans"] == 5      # wiring only: no latency assertion on a shared box
