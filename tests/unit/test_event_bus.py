import asyncio

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
    await bus.publish(StageStarted(stage="host"))
    await bus.publish(FindingDiscovered(
        probe_id="x", title="t", algorithm="A",
        classification="info", severity="info",
    ))
    await bus.publish(StageCompleted(stage="host"))
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
