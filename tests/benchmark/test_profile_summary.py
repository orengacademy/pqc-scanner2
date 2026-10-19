import json
import logging
import shutil
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import _collector, _profile

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


def test_summarise_divides_statements_by_stored_scans_and_writes_both_files(tmp_path):
    (tmp_path / "pyspy.collapsed.txt").write_text(RAW)
    (tmp_path / "statements.json").write_text(json.dumps({"source": "sqlite3 trace callback", "total_statements": 250,
                                                          "top": [{"sql": "INSERT INTO finding", "count": 200}]}))
    (tmp_path / "asyncio-slow.log").write_text("Executing <Handle ingest()> took 0.250 seconds\n")
    s = _profile.summarise(tmp_path, ingest_requests=10, enroll_requests=5, wall_s=30.0,
                           run={"db": "sqlite", "hosts": 5, "offered_rps": 1, "findings_per_bundle": 200, "commit": "abc",
                                "stored_scans": 5, "seed": 1, "command": "python -m benchmark.fleet.run_load x"})
    assert s["statements_per_ingest"] == 50.0                      # divided by stored scans, not ingest requests
    assert s["run"]["seed"] == 1 and s["run"]["command"].endswith("run_load x")
    assert s["slow_callbacks"]["count"] == 1 and s["slow_callbacks"]["max_s"] == 0.25
    assert json.loads((tmp_path / "summary.json").read_text())["statements_total"] == 250
    assert "`loads (json)`" in (tmp_path / "summary.md").read_text()


def test_statement_counter_samples_are_reported_apart_not_ranked(tmp_path):
    p = tmp_path / "pyspy.collapsed.txt"
    p.write_text(RAW + "thread (123);run (uvicorn);execute;_count (benchmark/fleet/_collector.py:140);sub (re) 50\n"
                 "thread (123);run (uvicorn);extract (traceback.py:449);checkcache (linecache.py:72) 50\n")
    assert _profile.instrumentation_pct(p) == 50.0
    by = {t["frame"]: t for t in _profile.top_frames(p)}
    assert not {"sub (re)", "checkcache (linecache.py:72)", "_count (benchmark/fleet/_collector.py:140)"} & set(by)
    assert by["loads (json)"]["self_pct"] == 30.0                  # still a share of all samples


def test_sqlite_profile_hooks_count_statements_and_detach(tmp_path):
    prof = tmp_path / "p"
    with _collector.collector("sqlite", tmp_path, profile_dir=prof) as url:
        assert httpx.get(f"{url}/api/fleet").status_code == 200
    assert json.loads((prof / "statements.json").read_text())["total_statements"] > 0
    assert (prof / "asyncio-slow.log").exists()
    log = str(prof / "asyncio-slow.log")
    assert all(getattr(h, "baseFilename", None) != log for h in logging.getLogger("asyncio").handlers)


def test_pyspy_raises_when_the_recorder_fails_but_never_masks_the_body(tmp_path, monkeypatch):
    monkeypatch.setattr(_profile.os, "geteuid", lambda: 0)         # no sudo prefix: run the fake recorder directly
    false = shutil.which("false")
    monkeypatch.setattr(_profile.shutil, "which", lambda *a, **k: false)
    with pytest.raises(RuntimeError, match="py-spy failed"), _profile.pyspy(1, tmp_path):
        pass
    with pytest.raises(ValueError), _profile.pyspy(1, tmp_path):
        raise ValueError("the run's own failure")


def test_slow_callback_log_survives_uvicorns_logging_config(tmp_path, monkeypatch):
    real = _collector.create_app

    def with_blocking_route(*a, **k):              # test-only route on the app object, not in the product
        app = real(*a, **k)

        async def block():
            import time
            time.sleep(0.3)  # noqa: ASYNC251 - blocks the event loop on purpose: a slow callback by construction
            return {}

        app.add_api_route("/test-block", block)
        return app

    monkeypatch.setattr(_collector, "create_app", with_blocking_route)
    prof = tmp_path / "p"
    with _collector.collector("sqlite", tmp_path, profile_dir=prof) as url:
        assert httpx.get(f"{url}/test-block").status_code == 200
    text = (prof / "asyncio-slow.log").read_text()
    assert text.startswith(_collector.SLOW_LOG_MARKER)
    assert "Executing" in text and " took " in text
    assert _profile.slow_callbacks(prof / "asyncio-slow.log")["count"] >= 1


def test_slow_callbacks_tell_not_captured_from_zero(tmp_path):
    log = tmp_path / "asyncio-slow.log"
    assert _profile.slow_callbacks(log)["captured"] is False       # absent
    log.write_text("")
    assert _profile.slow_callbacks(log)["captured"] is False       # empty: the pre-fix harness lost its handler
    log.write_text(_collector.SLOW_LOG_MARKER + "\n")
    s = _profile.slow_callbacks(log)
    assert s["captured"] is True and s["count"] == 0


def test_slow_callbacks_group_distinct_callbacks_with_counts(tmp_path):
    log = tmp_path / "asyncio-slow.log"
    task = ("Executing <Task {state} name='call_next.<locals>.coro' coro=<TaskHandle._run_coro() running at x.py:1> "
            "cb=[f() at y.py:2] created at z.py:3> took {s} seconds")
    log.write_text("\n".join([_collector.SLOW_LOG_MARKER, task.format(state="pending", s="0.300"),
                              task.format(state="cancelling", s="0.200"),
                              "Executing <Handle WorkerThread._report_result(<Future>) created at a.py:1> took 0.150 seconds",
                              "Executing <Task pending name='Task-1' coro=<Server.serve() running at b.py:2> took 0.120 seconds",
                              "Executing <TimerHandle when=5.0 _set_result_unless_cancelled() created at c.py:3> took 0.110 seconds"]))
    s = _profile.slow_callbacks(log)
    assert s["count"] == 5
    assert s["callbacks"][0] == {"callback": "Task call_next.<locals>.coro (TaskHandle._run_coro)", "count": 2,
                                 "max_s": 0.3}
    assert [c["callback"] for c in s["callbacks"][1:]] == [
        "Handle WorkerThread._report_result", "Task Task-N (Server.serve)", "TimerHandle _set_result_unless_cancelled"]
