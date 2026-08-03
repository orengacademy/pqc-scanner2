import asyncio
import threading

import pytest

from pqcscan.runner.event_bus import (
    EventBus,
    FindingDiscovered,
    ScanCompleted,
    StageCompleted,
    StageStarted,
)


@pytest.mark.asyncio
async def test_pub_sub_one_subscriber():
    bus = EventBus()
    received: list = []

    async def consumer():
        async for ev in bus.subscribe():
            received.append(ev)
            if isinstance(ev, ScanCompleted):
                break

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)
    await bus.publish(StageStarted(scan_id=1, stage="host"))
    await bus.publish(FindingDiscovered(
        scan_id=1, probe_id="x", title="t", algorithm="A",
        classification="info", severity="info",
    ))
    await bus.publish(StageCompleted(scan_id=1, stage="host"))
    await bus.publish(ScanCompleted(scan_id=1))
    await asyncio.wait_for(task, timeout=1.0)

    assert len(received) == 4
    assert isinstance(received[-1], ScanCompleted)


@pytest.mark.asyncio
async def test_two_subscribers_get_same_events():
    bus = EventBus()
    a, b = [], []

    async def consume(out):
        async for ev in bus.subscribe():
            out.append(ev)
            if isinstance(ev, ScanCompleted):
                return

    t1 = asyncio.create_task(consume(a))
    t2 = asyncio.create_task(consume(b))
    await asyncio.sleep(0)
    await bus.publish(ScanCompleted(scan_id=1))
    await asyncio.gather(t1, t2)
    assert len(a) == 1 and len(b) == 1


@pytest.mark.asyncio
async def test_publish_from_another_threads_loop_is_delivered():
    """The daemon runs scans in a background thread with its own event loop
    while SSE subscribers await on the server loop; publishes must cross that
    boundary safely (asyncio.Queue alone is not thread/loop-safe)."""
    bus = EventBus()
    received: list = []

    async def consumer():
        async for ev in bus.subscribe():
            received.append(ev)
            return

    task = asyncio.create_task(consumer())
    # Let the consumer reach `await q.get()` so the cross-thread wakeup path
    # (not just a queue append) is exercised.
    await asyncio.sleep(0.05)

    def _publish_from_thread() -> None:
        asyncio.run(bus.publish(StageStarted(scan_id=7, stage="network")))

    th = threading.Thread(target=_publish_from_thread)
    th.start()
    for _ in range(100):
        if received:
            break
        await asyncio.sleep(0.02)
    th.join(timeout=1.0)
    await asyncio.wait_for(task, timeout=1.0)

    assert received == [StageStarted(scan_id=7, stage="network")]
