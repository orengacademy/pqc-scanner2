"""Regression tests for the seven post-audit backlog fixes."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

# ---- item 4: no naive/aware deprecation, stable naive-UTC semantics --------

def test_utcnow_helper_is_naive_utc():
    from pqcscan.util.clock import utcnow
    now = utcnow()
    ref = datetime.now(UTC).replace(tzinfo=None)
    assert now.tzinfo is None                    # naive, matches legacy storage
    assert abs((ref - now).total_seconds()) < 5


def test_no_datetime_utcnow_left_in_src():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2] / "src" / "pqcscan"
    offenders = [
        p for p in root.rglob("*.py")
        if "datetime.utcnow(" in p.read_text() and p.name != "clock.py"
    ]
    assert not offenders, f"datetime.utcnow() still used in: {offenders}"


# ---- item 1: stale 'running' scans reconciled on startup -------------------

def test_reconcile_marks_stale_running_as_interrupted(tmp_db_path):
    from pqcscan.store.repo import Repo
    repo = Repo(tmp_db_path); repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    assert repo.get_scan(sid).status == "running"
    n = repo.reconcile_running_scans()
    assert n == 1
    assert repo.get_scan(sid).status == "interrupted"


def test_reconcile_leaves_done_scans_untouched(tmp_db_path):
    from pqcscan.store.repo import Repo
    repo = Repo(tmp_db_path); repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.finish_scan(sid, status="done")
    assert repo.reconcile_running_scans() == 0
    assert repo.get_scan(sid).status == "done"


def test_create_app_reconciles_on_startup(tmp_db_path):
    from pqcscan.store.repo import Repo
    seed = Repo(tmp_db_path); seed.init_schema()
    sid = seed.create_scan(mode="user", probe_versions={}, tool_versions={})

    from pqcscan.daemon.app import create_app
    create_app(db_path=tmp_db_path)
    assert Repo(tmp_db_path).get_scan(sid).status == "interrupted"


# ---- item 3: dashboard trend uses one bulk query, not N -------------------

def test_list_findings_bulk_groups_by_scan(tmp_db_path):
    from pqcscan.core.types import Classification, Finding, Severity
    from pqcscan.store.repo import Repo
    repo = Repo(tmp_db_path); repo.init_schema()
    ids = []
    for _ in range(3):
        sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
        repo.record_finding(sid, Finding(
            probe_id="p", algorithm="RSA-2048",
            classification=Classification.TINGGI, severity=Severity.HIGH, title="t",
        ))
        ids.append(sid)
    grouped = repo.list_findings_bulk(ids)
    assert set(grouped) == set(ids)
    assert all(len(v) == 1 for v in grouped.values())


def test_list_findings_bulk_empty_ids_is_empty(tmp_db_path):
    from pqcscan.store.repo import Repo
    repo = Repo(tmp_db_path); repo.init_schema()
    assert repo.list_findings_bulk([]) == {}


# ---- item 5: SSE stream emits a keepalive when idle -----------------------

async def test_sse_stream_emits_keepalive_on_idle():
    from pqcscan.daemon.sse import sse_stream
    from pqcscan.runner.event_bus import EventBus

    bus = EventBus()
    gen = sse_stream(bus, scan_id=1, heartbeat_s=0.05)
    chunk = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert chunk.startswith(":")                 # SSE comment = keepalive
    await gen.aclose()


async def test_sse_stream_forwards_matching_events():
    from pqcscan.daemon.sse import sse_stream
    from pqcscan.runner.event_bus import EventBus, StageStarted

    bus = EventBus()
    gen = sse_stream(bus, scan_id=7, heartbeat_s=5.0)
    task = asyncio.create_task(gen.__anext__())
    await asyncio.sleep(0.05)
    await bus.publish(StageStarted(scan_id=7, stage="host"))
    chunk = await asyncio.wait_for(task, timeout=1.0)
    assert "event: stage_started" in chunk
    await gen.aclose()


async def test_sse_stream_filters_other_scans():
    from pqcscan.daemon.sse import sse_stream
    from pqcscan.runner.event_bus import EventBus, StageStarted

    bus = EventBus()
    gen = sse_stream(bus, scan_id=1, heartbeat_s=0.05)
    await bus.publish(StageStarted(scan_id=999, stage="host"))  # other scan
    # First thing we get is the keepalive, never the other scan's event.
    chunk = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert chunk.startswith(":")
    await gen.aclose()


# ---- item 7: compliance key-size extraction takes the modulus, not the -----
#      first stray integer in a name like "SHA-3-512".

@pytest.mark.parametrize("alg,key,threshold,expected", [
    ("RSA-2048", "key_size_lt", 3072, True),
    ("RSA-4096", "key_size_lt", 3072, False),
    # The largest integer is the size: "SHA-3-512" must read as 512, not the
    # leading "3" — under key_size_ge 512 the old first-int logic gave False.
    ("SHA-3-512", "key_size_ge", 512, True),
    ("SHA-3-512", "key_size_lt", 256, False),
    ("AES-128", "key_size_lt", 3072, True),
])
def test_key_size_uses_largest_integer(alg, key, threshold, expected):
    from pqcscan.compliance.engine import _matches
    from pqcscan.core.types import Classification, Finding, Severity
    f = Finding(
        probe_id="p", algorithm=alg,
        classification=Classification.TINGGI, severity=Severity.HIGH, title="t",
    )
    assert _matches(key, threshold, f) is expected
