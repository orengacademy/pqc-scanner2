from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import AsyncGenerator
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class StageStarted:
    scan_id: int
    stage: str


@dataclass(slots=True, frozen=True)
class StageCompleted:
    scan_id: int
    stage: str


@dataclass(slots=True, frozen=True)
class FindingDiscovered:
    scan_id: int
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
    """In-memory pub/sub: each subscribe() returns its own queue.

    Publishers and subscribers may live on different event loops — the daemon
    runs each scan in a background thread with its own loop while SSE
    subscribers await on the server loop. asyncio.Queue is not thread-safe,
    so delivery to a foreign loop goes through call_soon_threadsafe; the
    subscriber list itself is guarded by a threading.Lock (an asyncio.Lock
    would be bound to whichever loop awaited it first).
    """

    def __init__(self) -> None:
        self._subscribers: list[
            tuple[asyncio.Queue[Event], asyncio.AbstractEventLoop]
        ] = []
        self._lock = threading.Lock()

    async def publish(self, event: Event) -> None:
        current = asyncio.get_running_loop()
        with self._lock:
            subs = list(self._subscribers)
        for q, loop in subs:
            if loop is current:
                q.put_nowait(event)
            else:
                # RuntimeError: subscriber's loop already closed; its
                # generator's finally block removes the queue on teardown.
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(q.put_nowait, event)

    async def subscribe(self) -> AsyncGenerator[Event, None]:
        q: asyncio.Queue[Event] = asyncio.Queue()
        loop = asyncio.get_running_loop()
        with self._lock:
            self._subscribers.append((q, loop))
        try:
            while True:
                yield await q.get()
        finally:
            with self._lock:
                self._subscribers = [
                    (sq, sl) for sq, sl in self._subscribers if sq is not q
                ]
