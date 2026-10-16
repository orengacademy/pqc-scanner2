from __future__ import annotations

import asyncio
import hmac
import ipaddress
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

from pqcscan import __version__
from pqcscan.daemon.sse import sse_stream
from pqcscan.probes._registry import Registry, default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.runner.targets import parse_scan_inputs
from pqcscan.store.repo import Repo
from pqcscan.store.schema import Scan

SESSION_COOKIE = "pqcscan_session"
_MAX_CONCURRENT_RENDERS = 2


def acquire_render_slot(app: FastAPI) -> None:
    """Take a render slot or raise 429; release with app.state.render_slots.release()."""
    if not app.state.render_slots.acquire(blocking=False):
        raise HTTPException(429, "too many concurrent exports; retry shortly")

_LOGIN_FORM = """<!doctype html><title>pqcscan login</title>
<form method="post" action="/login" style="font-family:sans-serif;margin:3em">
<label>Token <input type="password" name="token" autofocus></label>
<button>Sign in</button></form>"""


def is_loopback(bind: str) -> bool:
    """True for 127.0.0.0/8, ::1 and 'localhost'."""
    if bind in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(bind.strip("[]")).is_loopback
    except ValueError:
        return False


def _origin_matches_host(request: Request) -> bool:
    """CSRF guard: a browser-sent Origin must match the Host we were reached
    on. Non-browser clients send no Origin and pass."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return not origin
    return urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()


def create_app(
    *, db_path: Path, registry: Registry | None = None, token: str | None = None,
) -> FastAPI:
    """Build the daemon app.

    `token` (or $PQCSCAN_TOKEN) enables authentication: every request must
    carry `Authorization: Bearer <token>` or a session cookie obtained by
    POSTing the token to `/login` (a form; the token never travels in a URL,
    so it stays out of access logs and browser history). Sessions are random
    ids held in memory, so a restart logs browsers out. Without a token the
    daemon trusts whoever can reach the socket, which is only acceptable on
    loopback — `pqcscan daemon` refuses a non-loopback --bind without one.
    """
    app = FastAPI(title="pqcscan", version=__version__)
    token = token if token is not None else os.environ.get("PQCSCAN_TOKEN") or None
    sessions: set[str] = set()

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS") and not _origin_matches_host(request):
            return JSONResponse({"detail": "cross-origin request rejected"}, status_code=403)
        if token and request.url.path not in ("/api/health", "/login"):
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                ok = hmac.compare_digest(auth[7:].strip().encode(), token.encode())
            else:
                ok = request.cookies.get(SESSION_COOKIE, "") in sessions
            if not ok:
                if "text/html" in request.headers.get("accept", ""):
                    return RedirectResponse("/login", status_code=303)
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return await call_next(request)

    @app.get("/login", response_class=HTMLResponse)
    async def login_form() -> str:
        return _LOGIN_FORM

    @app.post("/login")
    async def login(token_form: str = Form("", alias="token")) -> Response:
        """Exchange the token (form body, never a URL) for a random session id."""
        if not token or not hmac.compare_digest(token_form.encode(), token.encode()):
            raise HTTPException(401, "bad token")
        sid = secrets.token_urlsafe(32)
        sessions.add(sid)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="strict", path="/")
        return resp
    repo = Repo(db_path)
    repo.init_schema()
    # Sweep scans left 'running' by a previous crash/restart so the
    # one-scan-at-a-time guard isn't wedged by a dead scan.
    repo.reconcile_running_scans()
    bus = EventBus()
    if registry is None:
        registry = default_registry()
    runner = ProbeRunner(registry=registry, repo=repo, bus=bus)

    import threading

    app.state.repo = repo
    app.state.bus = bus
    app.state.runner = runner
    # Serialises the check-and-claim of a new scan across concurrent requests
    # (single uvicorn process → a threading.Lock is sufficient).
    app.state.scan_lock = threading.Lock()
    # Heavy renders (PDF/XLSX/CBOM, HTML reports) are a cheap GET for a client
    # and an expensive in-memory render for us: cap concurrency, 429 beyond.
    app.state.render_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_RENDERS)

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/version")
    async def version() -> dict:
        return {"version": __version__}

    @app.post("/api/scans", status_code=202)
    async def post_scan(body: dict = Body(default=None)) -> dict:
        mode = current_mode()
        caps = detect_capabilities()

        body = body or {}
        scan_paths, server_target, ot_targets = parse_scan_inputs(
            target=body.get("target"),
            paths=body.get("paths"),
            ot=body.get("ot_targets"),
        )

        # Claim the scan row synchronously under a process lock: the check for
        # a running scan and the insert of the new 'running' row happen as one
        # atomic step, so two near-simultaneous POSTs can't both start.
        with app.state.scan_lock:
            scan_id = runner.begin_scan_if_idle(mode=mode)
        if scan_id is None:
            raise HTTPException(409, "a scan is already running")

        # Run in a real OS thread with its own asyncio event loop so the scan
        # outlives the request-handler's loop (FastAPI TestClient and ASGI
        # workers both tear down per-request loops on completion).
        def _thread_target() -> None:
            asyncio.run(runner.run(
                mode=mode, available_capabilities=caps,
                scan_paths=scan_paths, server_target=server_target,
                ot_targets=ot_targets, scan_id=scan_id,
            ))

        import threading
        threading.Thread(target=_thread_target, daemon=True).start()
        return {"id": scan_id}

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
        return StreamingResponse(
            sse_stream(bus, scan_id), media_type="text/event-stream",
        )

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

    @app.get("/api/scans/{scan_id}/export/{fmt}")
    async def export_scan(scan_id: int, fmt: str, lang: str = "ms") -> Response:
        """Render a scan to one of 5 formats and return as a binary download.

        Mirrors the CLI surface (`pqcscan export --format <fmt>`) but pipes the
        result back through HTTP so the web UI's export buttons work without
        users having to touch the CLI. PDF formats degrade gracefully (HTTP 503
        with a helpful message) when the optional weasyprint dep is absent."""
        if repo.get_scan(scan_id) is None:
            raise HTTPException(404, "scan not found")

        import tempfile

        # slug -> (suffix, content-type, filename-base)
        _xlsx_ct = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        formats: dict[str, tuple[str, str, str]] = {
            "cbom": (".cdx.json", "application/vnd.cyclonedx+json", "cbom"),
            "sarif": (".sarif", "application/sarif+json", "findings"),
            "pdf-tech": (".pdf", "application/pdf", "report-technical"),
            "pdf-exec": (".pdf", "application/pdf", "report-executive"),
            "xlsx-bukukerja": (".xlsx", _xlsx_ct, "report-bukukerja"),
            "xlsx-generic": (".xlsx", _xlsx_ct, "report-findings"),
        }
        if fmt not in formats:
            raise HTTPException(400, f"unknown format: {fmt}")
        suffix, content_type, name = formats[fmt]

        acquire_render_slot(app)
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            if fmt == "cbom":
                import json as _json

                from pqcscan.cbom.builder import build_cbom
                tmp_path.write_text(_json.dumps(build_cbom(repo, scan_id), indent=2))
            elif fmt == "sarif":
                from pqcscan.renderers.sarif import render_sarif
                render_sarif(repo, scan_id, tmp_path)
            elif fmt == "pdf-tech":
                try:
                    from pqcscan.renderers.pdf_technical import render_pdf_technical
                    render_pdf_technical(repo, scan_id, tmp_path, lang=lang)
                except (ImportError, ModuleNotFoundError) as e:
                    raise HTTPException(
                        503,
                        "PDF export requires weasyprint + cairo/pango "
                        "runtime. Install with: pip install 'pqcscan[render]'. "
                        "Frozen binaries do not bundle PDF support; use CBOM "
                        "or XLSX export instead.",
                    ) from e
            elif fmt == "pdf-exec":
                try:
                    from pqcscan.renderers.pdf_executive import render_pdf_executive
                    render_pdf_executive(repo, scan_id, tmp_path, lang=lang)
                except (ImportError, ModuleNotFoundError) as e:
                    raise HTTPException(
                        503,
                        "PDF export requires weasyprint + cairo/pango "
                        "runtime. Install with: pip install 'pqcscan[render]'. "
                        "Frozen binaries do not bundle PDF support; use CBOM "
                        "or XLSX export instead.",
                    ) from e
            elif fmt == "xlsx-bukukerja":
                from pqcscan.renderers.xlsx_bukukerja import render_xlsx_bukukerja
                render_xlsx_bukukerja(repo, scan_id, tmp_path, locale=lang)
            elif fmt == "xlsx-generic":
                from pqcscan.renderers.xlsx_generic import render_xlsx_generic
                render_xlsx_generic(repo, scan_id, tmp_path)
            data = tmp_path.read_bytes()
        finally:
            tmp_path.unlink(missing_ok=True)
            app.state.render_slots.release()

        lang_tag = "-en" if (fmt == "xlsx-bukukerja" and lang == "en") else ""
        filename = f"pqcscan-scan{scan_id}-{name}{lang_tag}{suffix}"
        return Response(
            content=data,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

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
