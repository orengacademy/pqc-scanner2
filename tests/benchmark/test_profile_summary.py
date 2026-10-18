import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import _profile

RAW = """\
thread (123);run (uvicorn);_run_once (asyncio);ingest (fleet.py:150);load_bundle (bundle.py:140);loads (json) 60
thread (123);run (uvicorn);_run_once (asyncio);ingest (fleet.py:150);ingest_bundle (repo.py:470);execute 30
thread (123);run (uvicorn);_run_once (asyncio);_agent_host (fleet.py:95) 10
"""


def test_top_frames_shares_by_self_and_total(tmp_path):
    p = tmp_path / "pyspy.collapsed.txt"
    p.write_text(RAW)
    top = _profile.top_frames(p)                   # ingest has no self time: outside a top three by self
    by = {t["frame"]: t for t in top}
    assert by["loads (json)"]["self_pct"] == 60.0
    assert by["ingest (fleet.py:150)"]["total_pct"] == 90.0
    assert top[0]["frame"] == "loads (json)"       # ordered by self share


def test_summarise_divides_statements_by_ingests_and_writes_both_files(tmp_path):
    (tmp_path / "pyspy.collapsed.txt").write_text(RAW)
    (tmp_path / "statements.json").write_text(json.dumps({"source": "sqlite3 trace callback", "total_statements": 250,
                                                          "top": [{"sql": "INSERT INTO finding", "count": 200}]}))
    (tmp_path / "asyncio-slow.log").write_text("Executing <Handle ingest()> took 0.250 seconds\n")
    s = _profile.summarise(tmp_path, ingest_requests=10, enroll_requests=5, wall_s=30.0,
                           run={"db": "sqlite", "hosts": 5, "offered_rps": 1, "findings_per_bundle": 200, "commit": "abc"})
    assert s["statements_per_ingest"] == 25.0
    assert s["slow_callbacks"]["count"] == 1 and s["slow_callbacks"]["max_s"] == 0.25
    assert json.loads((tmp_path / "summary.json").read_text())["statements_total"] == 250
    assert "`loads (json)`" in (tmp_path / "summary.md").read_text()
