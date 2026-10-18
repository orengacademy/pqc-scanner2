"""Fleet collector endpoints: agent enrollment, bundle ingest, fleet summary.

Auth model: /api/agents/enroll takes the shared enrollment token in the body
and mints a per-agent bearer token (stored SHA-256). /api/ingest accepts only
that bearer, never the site session cookie. Both are exempt from the site
cookie/token guard; the fleet read endpoints use the normal site guard.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from loguru import logger
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.concurrency import run_in_threadpool

from pqcscan.store.bundle import (
    MAX_GZIP_BYTES,
    BundleInvalid,
    BundleTooLarge,
    HostIdentity,
    check_labels,
    load_bundle,
)
from pqcscan.store.repo import Repo

FLEET_BEARER_PATHS = ("/api/ingest", "/api/agents/enroll")
INGEST_MIN_INTERVAL_S = 60.0   # one ingest token refilled per interval, per host
INGEST_BURST = 10               # tokens a host can spend at once (spool replay after an outage)
INGEST_PARALLELISM = 2          # bundles parsed/stored at once, across all hosts
INGEST_QUEUE_MAX = 32   # bundles waiting for or holding a parse slot, all hosts. Longest wait ≈ QUEUE_MAX x service
                        # time / INGEST_PARALLELISM; at 2 s per large bundle and 2 slots that is 32 s, under the
                        # agent's 60 s timeout, so a queued request is served, never abandoned. Past the bound the
                        # collector answers 503 + Retry-After and the agent spools (FLEET.md, Ingest limits).
MAX_ENROLL_BYTES = 64 * 1024
_TERMINAL_STATUSES = ("done", "failed", "interrupted")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class _TokenBucket:
    """Per-key bucket of INGEST_BURST tokens, one refilled every INGEST_MIN_INTERVAL_S.

    Both constants are read at call time so tests can patch them."""

    def __init__(self) -> None:
        self._state: dict[int, tuple[float, float]] = {}   # key -> (tokens, monotonic time)
        self._lock = threading.Lock()

    def take(self, key: int) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, then = self._state.get(key, (float(INGEST_BURST), now))
            tokens = (min(float(INGEST_BURST), tokens + (now - then) / INGEST_MIN_INTERVAL_S)
                      if INGEST_MIN_INTERVAL_S > 0 else float(INGEST_BURST))
            ok = tokens >= 1
            self._state[key] = (tokens - 1 if ok else tokens, now)
            return ok



async def _read_capped(request: Request, cap: int) -> bytes:
    """Request body, 413 past `cap` bytes; chunked uploads carry no Content-Length, so cap while reading."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > cap:
        raise HTTPException(413, f"body over {cap} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > cap:
            raise HTTPException(413, f"body over {cap} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _host_dict(h: Any) -> dict[str, Any]:
    return {"host_id": h.id, "machine_id": h.machine_id, "hostname": h.hostname, "os": h.os,
            "labels": h.labels or {}, "agent_version": h.agent_version,
            "first_seen": h.first_seen.isoformat() if h.first_seen else None,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None, "revoked": bool(h.revoked)}


def build_fleet_router(repo: Repo, *, enroll_token: str | None, keep_scans_per_host: int = 12) -> APIRouter:
    router = APIRouter()
    limiter = _TokenBucket()
    # Per router (one per app): an asyncio.Semaphore binds to the loop it first blocks on.
    parse_slots = asyncio.Semaphore(INGEST_PARALLELISM)
    queued = 0      # ingest requests past the queue check and not yet out of parse-and-store

    async def _agent_host(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "agent token required")
        try:
            host = await run_in_threadpool(repo.get_host_by_token_hash, hash_token(auth[7:].strip()))
        except OperationalError as e:
            raise HTTPException(503, "store busy, retry later", headers={"Retry-After": "5"}) from e
        if host is None or host.revoked:
            raise HTTPException(401, "unknown or revoked agent token")
        return host

    @router.post("/api/agents/enroll", status_code=201)
    async def enroll(request: Request) -> dict:
        if not enroll_token:              # before reading the body: this endpoint is pre-auth
            raise HTTPException(503, "enrollment disabled: daemon started without --enroll-token")
        try:
            body = json.loads(await _read_capped(request, MAX_ENROLL_BYTES))
        except (ValueError, RecursionError) as e:
            raise HTTPException(400, "body must be JSON") from e
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a JSON object")
        presented = str(body.get("enroll_token") or "")
        if not hmac.compare_digest(presented.encode(), enroll_token.encode()):
            raise HTTPException(403, "bad enrollment token")
        h = body.get("host")
        if not isinstance(h, dict) or not h.get("machine_id"):
            raise HTTPException(400, "host.machine_id required")
        labels = h.get("labels") or {}
        if not isinstance(labels, dict):
            raise HTTPException(400, "host.labels must be an object")
        labels = {str(k): str(v) for k, v in labels.items()}
        try:
            check_labels(labels)
        except BundleInvalid as e:
            raise HTTPException(400, str(e)) from e
        ident = HostIdentity(machine_id=str(h["machine_id"]), hostname=str(h.get("hostname", "")),
                             os=str(h.get("os", "")), labels=labels, agent_version=str(h.get("agent_version", "")))
        busy = HTTPException(503, "store busy, retry later", headers={"Retry-After": "5"})
        try:        # off the event loop: a write waiting on SQLite's lock must not stall every other request
            prior = await run_in_threadpool(repo.get_host_by_machine_id, ident.machine_id)
        except OperationalError as e:
            raise busy from e
        if prior is not None and prior.revoked:
            raise HTTPException(403, f"host is revoked; an operator must run `pqcscan agents unrevoke {prior.id}`")
        if prior is not None and prior.token_hash:
            logger.warning("fleet: re-enrollment rotated the token for host {} ({})", ident.hostname, ident.machine_id)
        token = secrets.token_urlsafe(32)
        try:
            host = await run_in_threadpool(repo.upsert_host, ident, token_hash=hash_token(token))
        except OperationalError as e:
            raise busy from e
        logger.info("fleet: enrolled host {} ({})", host.hostname, host.machine_id)
        return {"host_id": host.id, "agent_token": token}

    @router.post("/api/ingest")
    async def ingest(request: Request) -> dict:
        nonlocal queued
        host = await _agent_host(request)
        if not limiter.take(host.id):     # before reading or parsing anything
            raise HTTPException(429, f"ingest rate limit: {INGEST_BURST} bundles, then one per "
                                     f"{INGEST_MIN_INTERVAL_S:g} s per host")
        # Every outcome spends the token, duplicates included: a free resend would let one agent token push
        # 50 MiB through the parser endlessly, and the burst already absorbs a rare retry after a lost response.
        if queued >= INGEST_QUEUE_MAX:    # before reading the body; one event loop, so the count needs no lock
            raise HTTPException(503, f"collector busy: ingest queue full ({INGEST_QUEUE_MAX} bundles); "
                                     "the agent spools and retries", headers={"Retry-After": "60"})
        queued += 1
        try:
            data = await _read_capped(request, MAX_GZIP_BYTES)
            async with parse_slots:
                try:
                    bundle = await run_in_threadpool(load_bundle, data)
                except BundleTooLarge as e:
                    raise HTTPException(413, str(e)) from e
                except BundleInvalid as e:
                    raise HTTPException(400, str(e)) from e
                if bundle.host.machine_id != host.machine_id:
                    raise HTTPException(403, "bundle machine_id does not match the agent token")
                status = bundle.scan.get("status")
                if status not in _TERMINAL_STATUSES:
                    raise HTTPException(400, f"scan status {status!r} is not terminal; "
                                             f"expected one of {_TERMINAL_STATUSES}")
                try:
                    res = await run_in_threadpool(repo.ingest_bundle, bundle, host.id)
                except (ValueError, KeyError, TypeError) as e:
                    raise HTTPException(400, f"invalid bundle content: {e}") from e
                except OperationalError as e:     # e.g. SQLite busy past its timeout: the agent spools and retries
                    raise HTTPException(503, "store busy, retry later", headers={"Retry-After": "5"}) from e
                except IntegrityError as e:
                    # Two requests with the same scan_uuid raced past the duplicate check; the loser is a duplicate.
                    try:
                        existing = await run_in_threadpool(repo.get_scan_id_by_uuid, bundle.scan_uuid)
                    except OperationalError as e2:
                        raise HTTPException(503, "store busy, retry later", headers={"Retry-After": "5"}) from e2
                    if existing is None:
                        raise HTTPException(400, "bundle violates a store constraint") from e
                    return {"scan_id": existing, "stored_findings": 0, "stored_views": 0, "duplicate": True}
        finally:
            queued -= 1
        if bundle.dropped_drift:
            logger.warning("fleet: dropped {} agent-sent fleet.drift rows from host {}", bundle.dropped_drift, host.id)
        # After the write (drift was computed against the older scans) and outside parse_slots: these only delete.
        if not res.duplicate:
            try:
                await run_in_threadpool(repo.prune_host, host.id, keep_scans_per_host)
                await run_in_threadpool(repo.delete_stale_rollups)
            except Exception:                 # the scan is stored; a failed trim must not make the agent resend
                logger.opt(exception=True).warning("fleet: retention prune failed for host {}", host.id)
        return {"scan_id": res.scan_id, "stored_findings": res.stored_findings,
                "stored_views": res.stored_views, "duplicate": res.duplicate, "drift": res.drift}

    @router.get("/api/fleet")
    async def fleet() -> list[dict]:
        return [{**_host_dict(x.host), "scan_id": x.scan_id,
                 "finished_at": x.finished_at.isoformat() if x.finished_at else None,
                 "readiness": x.readiness, "crit": x.crit, "high": x.high, "total": x.total,
                 "drift": x.drift}
                for x in await run_in_threadpool(repo.fleet_summary)]

    @router.get("/api/fleet/{host_id}")
    async def fleet_host(host_id: int) -> dict:
        host = repo.get_host(host_id)
        if host is None:
            raise HTTPException(404, "host not found")
        return {"host": _host_dict(host),
                "scans": [{"id": s.id, "started_at": s.started_at.isoformat(), "status": s.status,
                           "finished_at": s.finished_at.isoformat() if s.finished_at else None}
                          for s in repo.host_history(host_id)]}

    @router.post("/api/agents/{host_id}/revoke")
    async def revoke(host_id: int) -> dict:
        if not repo.revoke_host(host_id):
            raise HTTPException(404, "host not found")
        return {"revoked": True}

    return router
