import sys
from pathlib import Path

import pytest

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


def test_littles_not_evaluated_for_run_shorter_than_two_intervals():
    r = run_load.littles(hosts=5, interval_s=60.0, mean_ms=200.0, achieved_rps=0.5, duration_s=100)
    assert r["measurement_defect"] is None
    assert "shorter than two intervals" in r["measurement_defect_reason"]
    assert run_load.littles(hosts=5, interval_s=60.0, mean_ms=200.0, achieved_rps=0.08, duration_s=120)[
        "measurement_defect"] is False


def test_append_row_refuses_a_header_with_a_different_column_count(tmp_path):
    md = tmp_path / "LOAD.md"
    md.write_text("| date (UTC) | db | rps |\n|---|---|---|\n")
    with pytest.raises(RuntimeError, match="3-column header"):
        run_load._check_md_columns(md, run_load.ROW_COLUMNS)
    md.write_text(run_load._load_md_head())          # the header the harness writes matches the row it appends
    run_load._check_md_columns(md, run_load.ROW_COLUMNS)


def test_committed_load_md_matches_the_row_format():
    run_load._check_md_columns(run_load.HERE / "LOAD.md", run_load.ROW_COLUMNS)


def test_ingest_parallelism_flag_refuses_below_one():
    import argparse
    assert run_load._at_least_one("3") == 3
    with pytest.raises(argparse.ArgumentTypeError, match="at least 1"):
        run_load._at_least_one("0")


def test_collector_reports_the_resolved_ingest_parallelism(tmp_path):
    from benchmark.fleet import _collector
    from pqcscan.daemon.fleet import INGEST_PARALLELISM
    for given, want in ((None, INGEST_PARALLELISM), (3, 3)):
        info: dict = {}
        work = tmp_path / str(given)
        work.mkdir()
        with _collector.collector("sqlite", work, ingest_parallelism=given, info=info):
            pass
        assert info == {"ingest_parallelism": want}
