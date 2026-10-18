import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import run_load


def test_littles_law_matches_closed_loop_expectation():
    # 120 hosts, 60 s think time, 500 ms mean response: expected 120 / 60.5 = 1.983 rps
    r = run_load.littles(hosts=120, interval_s=60.0, mean_ms=500.0, achieved_rps=1.98)
    assert abs(r["littles_expected_rps"] - 1.983) < 0.01
    assert 0.99 < r["littles_ratio"] < 1.01
    assert r["measurement_defect"] is False


def test_littles_law_flags_lost_requests():
    r = run_load.littles(hosts=500, interval_s=60.0, mean_ms=60000.0, achieved_rps=3.6)
    # 500 / 120 s = 4.17 expected; achieved 3.6 is 0.86: outside 0.9..1.1
    assert r["measurement_defect"] is True
    assert "0.86" in r["measurement_defect_reason"]


def test_rate_derives_interval():
    assert run_load.interval_for(hosts=500, rate=2.0) == 250.0
