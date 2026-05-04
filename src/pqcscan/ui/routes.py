from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pqcscan.probes._registry import default_registry

if TYPE_CHECKING:
    from fastapi import FastAPI

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"
_FRAMEWORKS_DIR = (
    Path(__file__).parent.parent / "compliance" / "frameworks"
)

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
    return templates.TemplateResponse(
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
    return templates.TemplateResponse(
        request, "framework_detail.html", {"framework": fw},
    )


@router.get("/probes", response_class=HTMLResponse)
async def probes_list(request: Request) -> HTMLResponse:
    reg = default_registry()
    groups: "OrderedDict[str, list]" = OrderedDict()
    for probe in sorted(reg.all(), key=lambda p: (p.family.name, p.id)):
        groups.setdefault(probe.family.name, []).append(probe)
    return templates.TemplateResponse(
        request, "probes.html",
        {"groups": groups, "total": len(reg.ids())},
    )
