from __future__ import annotations

import sys
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pqcscan import __version__ as _pqc_version
from pqcscan.probes._registry import default_registry
from pqcscan.runner.capabilities import current_mode, detect_capabilities
from pqcscan.ui.i18n import (
    LOCALE_COOKIE,
    SUPPORTED_LOCALES,
    get_locale,
    t,
)

if TYPE_CHECKING:
    from fastapi import FastAPI

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"
_FRAMEWORKS_DIR = (
    Path(__file__).parent.parent / "compliance" / "frameworks"
)

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
router = APIRouter()


def mount_static(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


def _render(
    request: Request, template: str, context: dict | None = None,
) -> HTMLResponse:
    """Render a template with i18n helpers (locale + t) injected."""
    locale = get_locale(request)
    ctx: dict = {"locale": locale, "t": lambda k: t(k, locale)}
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, template, ctx)


@router.post("/i18n/{locale}")
async def set_locale(request: Request, locale: str) -> RedirectResponse:
    """Set the locale cookie and redirect to the referer (or '/')."""
    if locale not in SUPPORTED_LOCALES:
        raise HTTPException(400, "unsupported locale")
    target = request.headers.get("referer") or "/"
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(
        LOCALE_COOKIE, locale,
        max_age=31_536_000, path="/", samesite="lax",
    )
    return resp


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    scans = repo.list_scans()
    last_scan = scans[0] if scans else None
    return _render(
        request, "dashboard.html", {"last_scan": last_scan},
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_list(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    scans = repo.list_scans()
    return _render(
        request, "scans_list.html", {"scans": scans},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int) -> HTMLResponse:
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    findings = repo.list_findings(scan_id)
    return _render(
        request, "scan_detail.html", {"scan": scan, "findings": findings},
    )


def _load_framework(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@router.get("/frameworks", response_class=HTMLResponse)
async def frameworks_list(request: Request) -> HTMLResponse:
    rows: list[dict] = []
    if _FRAMEWORKS_DIR.is_dir():
        for path in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
            doc = _load_framework(path)
            rows.append({
                "name": doc.get("framework", path.stem),
                "title": doc.get("title", ""),
                "rule_count": len(doc.get("rules") or []),
                "path": str(path),
            })
    return _render(
        request, "frameworks.html", {"frameworks": rows},
    )


@router.get("/frameworks/{name}", response_class=HTMLResponse)
async def framework_detail(request: Request, name: str) -> HTMLResponse:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "invalid framework name")
    candidates = list(_FRAMEWORKS_DIR.glob(f"{name}.yaml"))
    if not candidates:
        for path in _FRAMEWORKS_DIR.glob("*.yaml"):
            if _load_framework(path).get("framework") == name:
                candidates = [path]
                break
    if not candidates:
        raise HTTPException(404, "framework not found")
    doc = _load_framework(candidates[0])
    fw = {
        "name": doc.get("framework", candidates[0].stem),
        "title": doc.get("title", ""),
        "rules": doc.get("rules") or [],
    }
    return _render(
        request, "framework_detail.html", {"framework": fw},
    )


@router.get("/probes", response_class=HTMLResponse)
async def probes_list(request: Request) -> HTMLResponse:
    reg = default_registry()
    groups: OrderedDict[str, list] = OrderedDict()
    for probe in sorted(reg.all(), key=lambda p: (p.family.name, p.id)):
        groups.setdefault(probe.family.name, []).append(probe)
    return _render(
        request, "probes.html",
        {"groups": groups, "total": len(reg.ids())},
    )


@router.post("/baselines/create")
async def create_baseline_form(
    request: Request,
    scan_id: int = Form(...),
    label: str = Form(...),
    notes: str | None = Form(None),
) -> RedirectResponse:
    repo = request.app.state.repo
    if not label.strip():
        raise HTTPException(400, "label is required")
    try:
        repo.create_baseline(
            scan_id=scan_id, label=label.strip(),
            notes=(notes.strip() if notes else None),
        )
    except ValueError as e:
        raise HTTPException(404, str(e)) from e
    return RedirectResponse("/baselines", status_code=303)


@router.get("/baselines", response_class=HTMLResponse)
async def baselines_list(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    return _render(
        request, "baselines.html",
        {"baselines": repo.list_baselines(), "scans": repo.list_scans()},
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    reg = default_registry()
    caps = sorted(c.value for c in detect_capabilities())
    info = {
        "version": _pqc_version,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "mode": current_mode(),
        "db_url": str(repo.engine.url),
        "capabilities": caps,
        "probe_count": len(reg.ids()),
        "framework_count": len(list(_FRAMEWORKS_DIR.glob("*.yaml"))),
    }
    return _render(request, "settings.html", {"info": info})


@router.get("/baselines/diff", response_class=HTMLResponse)
async def scan_diff(
    request: Request, scan: int, baseline_scan: int,
) -> HTMLResponse:
    repo = request.app.state.repo
    if repo.get_scan(scan) is None or repo.get_scan(baseline_scan) is None:
        raise HTTPException(404, "scan or baseline not found")
    diff = repo.diff_findings(
        current_scan_id=scan, baseline_scan_id=baseline_scan,
    )
    return _render(
        request, "scan_diff.html",
        {
            "current_scan_id": scan,
            "baseline_scan_id": baseline_scan,
            "added": diff["added"],
            "removed": diff["removed"],
            "common": diff["common"],
        },
    )
