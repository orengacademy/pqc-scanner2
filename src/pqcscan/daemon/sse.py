from __future__ import annotations

import json
from dataclasses import asdict

from pqcscan.runner.event_bus import (
    Event,
    FindingDiscovered,
    ScanCompleted,
    StageCompleted,
    StageStarted,
)


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
