from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import asdict

from pqcscan.runner.event_bus import (
    Event,
    EventBus,
    FindingDiscovered,
    ScanCompleted,
    StageCompleted,
    StageStarted,
)

# Default idle interval after which the stream emits an SSE comment so idle
# proxies/load-balancers don't drop a long-lived connection.
_HEARTBEAT_S = 15.0


def event_for_scan(event: Event, scan_id: int) -> bool:
    """True when `event` belongs to the given scan.

    Every bus event carries the scan_id it was published under, so per-scan
    SSE streams can drop events from concurrent scans."""
    return getattr(event, "scan_id", None) == scan_id


def event_to_sse(event: Event) -> str:
    """Encode an event as a single Server-Sent Events message."""
    if isinstance(event, StageStarted):
        kind = "stage_started"
    elif isinstance(event, StageCompleted):
        kind = "stage_completed"
    elif isinstance(event, FindingDiscovered):
        kind = "finding"
    elif isinstance(event, ScanCompleted):
        kind = "scan_completed"
    else:
        kind = "unknown"
    payload = json.dumps(asdict(event))
    return f"event: {kind}\ndata: {payload}\n\n"


async def sse_stream(
    bus: EventBus, scan_id: int, *, heartbeat_s: float = _HEARTBEAT_S
) -> AsyncIterator[str]:
    """Yield SSE text for one scan's events, with an idle keepalive.

    Forwards only events belonging to `scan_id`; when no event arrives within
    `heartbeat_s`, yields an SSE comment (`: keepalive`) so intermediaries
    keep the connection open."""
    agen = bus.subscribe()
    try:
        while True:
            try:
                ev = await asyncio.wait_for(agen.__anext__(), timeout=heartbeat_s)
            except TimeoutError:
                yield ": keepalive\n\n"
                continue
            except StopAsyncIteration:
                break
            if event_for_scan(ev, scan_id):
                yield event_to_sse(ev)
    finally:
        await agen.aclose()
