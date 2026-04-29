from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

if TYPE_CHECKING:
    from fastapi import FastAPI

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
router = APIRouter()


def mount_static(app: "FastAPI") -> None:
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    scans = repo.list_scans()
    last_scan = scans[0] if scans else None
    return templates.TemplateResponse(
        request, "dashboard.html", {"last_scan": last_scan},
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_list(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    scans = repo.list_scans()
    return templates.TemplateResponse(
        request, "scans_list.html", {"scans": scans},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int) -> HTMLResponse:
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    findings = repo.list_findings(scan_id)
    return templates.TemplateResponse(
        request, "scan_detail.html", {"scan": scan, "findings": findings},
    )
