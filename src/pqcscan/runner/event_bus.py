from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class StageStarted:
    stage: str


@dataclass(slots=True, frozen=True)
class StageCompleted:
    stage: str


@dataclass(slots=True, frozen=True)
class FindingDiscovered:
    probe_id: str
    title: str
    algorithm: str
    classification: str
    severity: str


@dataclass(slots=True, frozen=True)
class ScanCompleted:
    scan_id: int


Event = StageStarted | StageCompleted | FindingDiscovered | ScanCompleted


class EventBus:
    """In-memory pub/sub: each subscribe() returns its own queue."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._lock = asyncio.Lock()

    async def publish(self, event: Event) -> None:
        async with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            await q.put(event)

    async def subscribe(self) -> AsyncIterator[Event]:
        q: asyncio.Queue[Event] = asyncio.Queue()
        async with self._lock:
            self._subscribers.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                if q in self._subscribers:
                    self._subscribers.remove(q)
