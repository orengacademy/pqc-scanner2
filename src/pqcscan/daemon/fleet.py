"""Fleet collector endpoints: agent enrollment, bundle ingest, fleet summary.

Auth model: /api/agents/enroll takes the shared enrollment token in the body
and mints a per-agent bearer token (stored SHA-256). /api/ingest accepts only
that bearer, never the site session cookie. Both are exempt from the site
cookie/token guard; the fleet read endpoints use the normal site guard.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Request
from loguru import logger
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from pqcscan.store.bundle import (
    MAX_GZIP_BYTES,
    BundleInvalid,
    BundleTooLarge,
    HostIdentity,
    ScanBundle,
    load_bundle,
)
from pqcscan.store.repo import IngestResult, Repo

FLEET_BEARER_PATHS = ("/api/ingest", "/api/agents/enroll")
INGEST_MIN_INTERVAL_S = 60.0
_TERMINAL_STATUSES = ("done", "failed", "interrupted")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class _RateLimiter:
    """One hit per key per INGEST_MIN_INTERVAL_S; the interval is read at call time so tests can patch it."""

    def __init__(self) -> None:
        self._last: dict[int, float] = {}
        self._lock = threading.Lock()

    def allow(self, key: int) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < INGEST_MIN_INTERVAL_S:
                return False
            self._last[key] = now
            return True


def _host_dict(h: Any) -> dict[str, Any]:
    return {"host_id": h.id, "machine_id": h.machine_id, "hostname": h.hostname, "os": h.os,
            "labels": h.labels or {}, "agent_version": h.agent_version,
            "first_seen": h.first_seen.isoformat() if h.first_seen else None,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None, "revoked": bool(h.revoked)}


def build_fleet_router(repo: Repo, *, enroll_token: str | None) -> APIRouter:
    router = APIRouter()
    limiter = _RateLimiter()

    def _agent_host(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "agent token required")
        host = repo.get_host_by_token_hash(hash_token(auth[7:].strip()))
        if host is None or host.revoked:
            raise HTTPException(401, "unknown or revoked agent token")
        return host

    @router.post("/api/agents/enroll", status_code=201)
    async def enroll(body: dict = Body(...)) -> dict:
        if not enroll_token:
            raise HTTPException(503, "enrollment disabled: daemon started without --enroll-token")
        presented = str(body.get("enroll_token") or "")
        if not hmac.compare_digest(presented.encode(), enroll_token.encode()):
            raise HTTPException(403, "bad enrollment token")
        h = body.get("host")
        if not isinstance(h, dict) or not h.get("machine_id"):
            raise HTTPException(400, "host.machine_id required")
        labels = h.get("labels") or {}
        if not isinstance(labels, dict):
            raise HTTPException(400, "host.labels must be an object")
        ident = HostIdentity(machine_id=str(h["machine_id"]), hostname=str(h.get("hostname", "")),
                             os=str(h.get("os", "")), labels={str(k): str(v) for k, v in labels.items()},
                             agent_version=str(h.get("agent_version", "")))
        prior = repo.get_host_by_machine_id(ident.machine_id)
        if prior is not None and prior.revoked:
            raise HTTPException(403, f"host is revoked; an operator must run `pqcscan agents unrevoke {prior.id}`")
        if prior is not None and prior.token_hash:
            logger.warning("fleet: re-enrollment rotated the token for host {} ({})", ident.hostname, ident.machine_id)
        token = secrets.token_urlsafe(32)
        host = repo.upsert_host(ident, token_hash=hash_token(token))
        logger.info("fleet: enrolled host {} ({})", host.hostname, host.machine_id)
        return {"host_id": host.id, "agent_token": token}

    def _store(bundle: ScanBundle, host_id: int) -> IngestResult:
        repo.upsert_host(bundle.host)
        return repo.ingest_bundle(bundle, host_id)

    @router.post("/api/ingest")
    async def ingest(request: Request) -> dict:
        host = _agent_host(request)
        try:
            declared = int(request.headers.get("content-length") or 0)
        except ValueError:
            declared = 0
        if declared > MAX_GZIP_BYTES:
            raise HTTPException(413, f"bundle over {MAX_GZIP_BYTES} bytes")
        # Chunked uploads carry no Content-Length: enforce the cap while reading, not after.
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_GZIP_BYTES:
                raise HTTPException(413, f"bundle over {MAX_GZIP_BYTES} bytes")
            chunks.append(chunk)
        try:
            bundle = await run_in_threadpool(load_bundle, b"".join(chunks))
        except BundleTooLarge as e:
            raise HTTPException(413, str(e)) from e
        except BundleInvalid as e:
            raise HTTPException(400, str(e)) from e
        if bundle.host.machine_id != host.machine_id:
            raise HTTPException(403, "bundle machine_id does not match the agent token")
        status = bundle.scan.get("status")
        if status not in _TERMINAL_STATUSES:
            raise HTTPException(400, f"scan status {status!r} is not terminal; expected one of {_TERMINAL_STATUSES}")
        if not limiter.allow(host.id):
            raise HTTPException(429, "one bundle per minute per host")
        try:
            res = await run_in_threadpool(_store, bundle, host.id)
        except (ValueError, KeyError, TypeError) as e:
            raise HTTPException(400, f"invalid bundle content: {e}") from e
        except IntegrityError as e:
            # Two requests with the same scan_uuid raced past the duplicate check; the loser is a duplicate.
            existing = repo.get_scan_id_by_uuid(bundle.scan_uuid)
            if existing is None:
                raise HTTPException(400, "bundle violates a store constraint") from e
            return {"scan_id": existing, "stored_findings": 0, "stored_views": 0, "duplicate": True}
        return {"scan_id": res.scan_id, "stored_findings": res.stored_findings,
                "stored_views": res.stored_views, "duplicate": res.duplicate}

    @router.get("/api/fleet")
    async def fleet() -> list[dict]:
        return [{**_host_dict(x.host), "scan_id": x.scan_id,
                 "finished_at": x.finished_at.isoformat() if x.finished_at else None,
                 "readiness": x.readiness, "crit": x.crit, "high": x.high, "total": x.total}
                for x in repo.fleet_summary()]

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
