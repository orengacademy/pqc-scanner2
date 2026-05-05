from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import StreamingResponse

from pqcscan import __version__
from pqcscan.daemon.sse import event_to_sse
from pqcscan.probes._registry import Registry, default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo
from pqcscan.store.schema import Scan


def create_app(*, db_path: Path, registry: Registry | None = None) -> FastAPI:
    app = FastAPI(title="pqcscan", version=__version__)
    repo = Repo(db_path)
    repo.init_schema()
    bus = EventBus()
    if registry is None:
        registry = default_registry()
    runner = ProbeRunner(registry=registry, repo=repo, bus=bus)

    app.state.repo = repo
    app.state.bus = bus
    app.state.runner = runner

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/version")
    async def version() -> dict:
        return {"version": __version__}

    @app.post("/api/scans", status_code=202)
    async def post_scan() -> dict:
        mode = current_mode()
        caps = detect_capabilities()

        # Run in a real OS thread with its own asyncio event loop so the scan
        # outlives the request-handler's loop (FastAPI TestClient and ASGI
        # workers both tear down per-request loops on completion).
        def _thread_target() -> None:
            asyncio.run(runner.run(mode=mode, available_capabilities=caps))

        import threading
        thread = threading.Thread(target=_thread_target, daemon=True)
        thread.start()

        for _ in range(50):
            scans = repo.list_scans()
            if scans:
                return {"id": scans[0].id}
            await asyncio.sleep(0.02)
        raise HTTPException(500, "scan failed to start")

    @app.get("/api/scans")
    async def list_scans() -> list[dict]:
        return [_scan_to_dict(s) for s in repo.list_scans()]

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: int) -> dict:
        scan = repo.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, "not found")
        return _scan_to_dict(scan)

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(scan_id: int) -> list[dict]:
        rows = repo.list_findings(scan_id)
        return [
            {
                "id": r.id,
                "probe_id": r.probe_id,
                "algorithm": r.algorithm,
                "classification": r.classification,
                "severity": r.severity,
                "title": r.title,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]

    @app.get("/api/scans/{scan_id}/events")
    async def stream_events(scan_id: int) -> StreamingResponse:
        async def gen():
            async for ev in bus.subscribe():
                yield event_to_sse(ev)
        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/baselines", status_code=201)
    async def post_baseline(body: dict = Body(...)) -> dict:
        scan_id = body.get("scan_id")
        label = body.get("label")
        notes = body.get("notes")
        if not isinstance(scan_id, int) or not isinstance(label, str) or not label:
            raise HTTPException(400, "scan_id (int) and label (str) are required")
        try:
            bid = repo.create_baseline(
                scan_id=scan_id, label=label, notes=notes,
            )
        except ValueError as e:
            raise HTTPException(404, str(e)) from e
        return {"id": bid}

    @app.get("/api/baselines")
    async def list_baselines() -> list[dict]:
        return [
            {
                "id": b.id, "scan_id": b.scan_id, "label": b.label,
                "notes": b.notes, "created_at": b.created_at.isoformat(),
            }
            for b in repo.list_baselines()
        ]

    @app.get("/api/scans/{scan_id}/diff")
    async def diff_scan(scan_id: int, baseline_scan: int) -> dict:
        if repo.get_scan(scan_id) is None or repo.get_scan(baseline_scan) is None:
            raise HTTPException(404, "scan or baseline not found")
        diff = repo.diff_findings(
            current_scan_id=scan_id, baseline_scan_id=baseline_scan,
        )
        def _row(f):
            return {
                "id": f.id, "probe_id": f.probe_id, "algorithm": f.algorithm,
                "classification": f.classification, "severity": f.severity,
                "title": f.title,
            }
        return {
            "added": [_row(f) for f in diff["added"]],
            "removed": [_row(f) for f in diff["removed"]],
            "common": diff["common"],
        }

    # Mount the web UI (Jinja + HTMX + SSE).
    from pqcscan.ui.routes import mount_static
    from pqcscan.ui.routes import router as ui_router
    mount_static(app)
    app.include_router(ui_router)

    return app


def _scan_to_dict(s: Scan) -> dict:
    return {
        "id": s.id,
        "started_at": s.started_at.isoformat(),
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "status": s.status,
        "mode": s.mode,
        "label": s.label,
    }
