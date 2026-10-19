"""The fleet load harness end to end at toy size: 5 hosts, 10 s, SQLite. Proves the wiring, not the capacity."""
import gzip
import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import run_load

# find_spec, not importorskip: importing locust here would gevent-monkey-patch the pytest process and hang the
# collector thread. The harness runs locust in a subprocess.
if importlib.util.find_spec("locust") is None:
    pytest.skip("needs the `verify` extra (locust); ci.yml does not install it, verify.yml does", allow_module_level=True)

pytestmark = pytest.mark.benchmark


def test_five_hosts_ten_seconds_sqlite():
    r = run_load.run(db="sqlite", hosts=5, spawn_rate=5, duration_s=10, findings=50, stagger=False, record=False,
                     command="smoke")
    assert r["errors"] == 0, r["failure_samples"]
    assert r["requests"] == 5 and r["enroll_requests"] == 5      # one host, one bundle: interval is 60 s
    assert r["http_429"] == 0 and r["http_503"] == 0
    assert r["schema_version"] == 2 and "littles_ratio" in r    # Little's law is meaningless over a truncated run
    assert r["findings_per_bundle"] == 50
    assert r["stored_hosts"] == 5 and r["stored_scans"] == 5      # wiring only: no latency assertion on a shared box


def test_recorded_run_writes_gz_csvs_and_a_rate_named_result(tmp_path):
    md = tmp_path / "LOAD.md"
    r = run_load.run(db="sqlite", hosts=5, spawn_rate=5, duration_s=10, findings=50, rate=0.5, stagger=False,
                     record=True, results_dir=tmp_path, md_path=md, command="smoke")
    assert r["interval_s"] == 10.0 and r["offered_rps"] == 0.5
    assert r["measurement_defect"] is None                          # 10 s is one interval: not evaluated
    assert r["hosts_daily_2h_equiv"] == round(0.5 * 7200) and r["hosts_daily_24h_equiv"] == round(0.5 * 86400)
    assert "-r0.5" in r["result_file"] and json.loads((tmp_path / r["result_file"]).read_text())["schema_version"] == 2
    requests = gzip.decompress((tmp_path / r["requests_csv"]).read_bytes()).decode().splitlines()
    assert requests[0] == "ts,name,status,response_ms,bytes" and len(requests) > 1
    assert gzip.decompress((tmp_path / r["history_csv"]).read_bytes()).decode().startswith("Timestamp,User Count")
    assert md.read_text().count("\n| 20") == 1                      # head plus exactly one row
    unrecorded = run_load.run(db="sqlite", hosts=1, spawn_rate=1, duration_s=5, findings=10, record=False)
    assert unrecorded["requests_csv"] is None and unrecorded["history_csv"] is None
