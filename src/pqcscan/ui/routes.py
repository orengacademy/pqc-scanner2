from __future__ import annotations

import sys
from collections import OrderedDict
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pqcscan import __version__ as _pqc_version
from pqcscan.core.bands import (
    SURFACE_LABELS,
    SURFACE_ORDER,
    classify_band,
    count_bands,
    readiness_score,
    surface_breakdown,
)
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
# Expose the band classifier to Jinja templates so per-row colouring
# (green/yellow/red/grey) doesn't require precomputing a parallel list.
templates.env.globals["band_of"] = classify_band
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


# NACSA Arahan KE No. 9, Lampiran A §C — Pelan Garis Masa Migrasi PQC.
# (n, name_bm, name_en, start_date, end_date_or_none)
_NACSA_FASA: list[dict] = [
    {"n": 1, "name": "Persediaan",  "en": "Assess",
     "start": date(2025, 7, 1), "end": date(2025, 12, 31)},
    {"n": 2, "name": "Pemilihan",   "en": "Select",
     "start": date(2026, 1, 1), "end": date(2026, 6, 30)},
    {"n": 3, "name": "Pengesahan",  "en": "Validate",
     "start": date(2026, 7, 1), "end": date(2026, 12, 31)},
    {"n": 4, "name": "Pelaksanaan", "en": "Deploy",
     "start": date(2027, 1, 1), "end": date(2027, 6, 30)},
    {"n": 5, "name": "Pemantauan",  "en": "Monitor",
     "start": date(2027, 7, 1), "end": None},
]


def _current_fasa(today: date) -> int:
    """Return the active NACSA migration fasa (1..5) for `today`."""
    for fasa in _NACSA_FASA:
        start: date = fasa["start"]
        end: date | None = fasa["end"]
        n: int = fasa["n"]
        if today < start:
            return max(1, n - 1)  # haven't entered yet → previous
        if end is None or today <= end:
            return n
    return 5


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    scans = repo.list_scans()
    last_scan = scans[0] if scans else None

    bands = None
    surfaces = None
    score = None
    if last_scan is not None:
        findings = repo.list_findings(last_scan.id)
        bands = count_bands(findings)
        surfaces = surface_breakdown(findings)
        score = readiness_score(bands)

    # Last 30-day trend: take up to 30 most recent done-or-running scans
    # in chronological order so the sparkline reads left-to-right.
    trend = []
    for s in reversed(scans[:30]):
        s_bands = count_bands(repo.list_findings(s.id))
        trend.append({
            "id": s.id,
            "score": readiness_score(s_bands),
            "started_at": s.started_at,
        })

    today = date.today()
    nacsa_fasa = {
        "current": _current_fasa(today),
        "phases": _NACSA_FASA,
        "today": today,
    }

    return _render(
        request, "dashboard.html",
        {
            "last_scan": last_scan,
            "bands": bands,
            "surfaces": surfaces,
            "surface_order": SURFACE_ORDER,
            "surface_labels": SURFACE_LABELS,
            "readiness": score,
            "trend": trend,
            "recent_scans": scans[:5],
            "nacsa_fasa": nacsa_fasa,
        },
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_list(request: Request) -> HTMLResponse:
    repo = request.app.state.repo
    scans = repo.list_scans()
    return _render(
        request, "scans_list.html", {"scans": scans},
    )


@router.post("/scans/new")
async def start_scan(
    request: Request,
    target: str | None = Form(None),
    paths: str | None = Form(None),
    ot_targets: str | None = Form(None),
) -> RedirectResponse:
    """Trigger a scan from the web UI, optionally against a pasted target.

    `paths` / `ot_targets` are newline- or comma-separated. The scan runs in
    a background thread (its own event loop) so it outlives the request, then
    we redirect to the scan-detail page.
    """
    import asyncio
    import threading

    from pqcscan.runner.capabilities import current_mode, detect_capabilities
    from pqcscan.runner.targets import parse_scan_inputs

    runner = request.app.state.runner
    repo = request.app.state.repo

    def _split(raw: str | None) -> list[str]:
        if not raw:
            return []
        return [p.strip() for p in raw.replace(",", "\n").splitlines() if p.strip()]

    scan_paths, server_target, ot_list = parse_scan_inputs(
        target=target, paths=_split(paths), ot=_split(ot_targets),
    )
    mode = current_mode()
    caps = detect_capabilities()

    def _thread_target() -> None:
        asyncio.run(runner.run(
            mode=mode, available_capabilities=caps,
            scan_paths=scan_paths, server_target=server_target,
            ot_targets=ot_list,
        ))

    before = repo.list_scans()
    before_ids = {s.id for s in before}
    threading.Thread(target=_thread_target, daemon=True).start()

    # Wait briefly for the scan row to appear so we can deep-link to it.
    for _ in range(100):
        for s in repo.list_scans():
            if s.id not in before_ids:
                return RedirectResponse(f"/scans/{s.id}", status_code=303)
        await asyncio.sleep(0.02)
    return RedirectResponse("/scans", status_code=303)


@router.get("/scans/{scan_id}/risk", response_class=HTMLResponse)
async def risk_assessment(request: Request, scan_id: int) -> HTMLResponse:
    """Web view of BUKUKERJA Lampiran A Item B (Penilaian Risiko dan
    Kebergantungan) — Jadual 3 (Risk Register) + Jadual 4 (Risk &
    Dependency Assessment), rendered with the same dedup + locale-aware
    helpers as the xlsx export so the UI and the workbook match
    row-for-row."""
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    findings = repo.list_findings(scan_id)

    from pqcscan.renderers.xlsx_bukukerja import (
        _IMPACT_BY_CLASSIFICATION,
        _asset_name_for,
        _dedupe_risk,
        _jenis_aset,
        _kawalan_sedia_ada,
        _kegunaan_kripto,
        _likelihood_for,
        _pelan_mitigasi,
        _punca_risiko,
        _risk_level_label,
    )
    locale = get_locale(request)
    risk_findings = [
        f for f in findings
        if str(f.classification) in ("sangat-tinggi", "tinggi", "sederhana")
    ]
    risk_grouped = _dedupe_risk(risk_findings)

    register_rows = []
    assessment_rows = []
    level_counts: dict[str, int] = {}
    for idx, (f, count) in enumerate(risk_grouped, start=1):
        impact = _IMPACT_BY_CLASSIFICATION.get(str(f.classification), 1)
        likelihood = _likelihood_for(f.probe_id)
        score = impact * likelihood
        level = _risk_level_label(score, locale)
        level_counts[level] = level_counts.get(level, 0) + 1
        common = {
            "idx": idx,
            "asset": str(_asset_name_for(f))[:120],
            "algorithm": f.algorithm,
            "title": f.title,
            "classification": str(f.classification),
            "count": count,
        }
        register_rows.append({
            **common,
            "jenis_aset": _jenis_aset(f.probe_id, locale),
            "kegunaan": _kegunaan_kripto(f.probe_id, f.algorithm, locale),
        })
        assessment_rows.append({
            **common,
            "impact": impact,
            "likelihood": likelihood,
            "score": score,
            "level": level,
            "punca": _punca_risiko(f.probe_id, f.algorithm, locale),
            "kawalan": _kawalan_sedia_ada(f, locale),
            "mitigasi": _pelan_mitigasi(f.algorithm, locale),
        })

    return _render(
        request, "risk_assessment.html",
        {
            "scan": scan,
            "register_rows": register_rows,
            "assessment_rows": assessment_rows,
            "level_counts": level_counts,
            "total_unique": len(risk_grouped),
            "total_findings": len(risk_findings),
        },
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int) -> HTMLResponse:
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    findings = repo.list_findings(scan_id)
    bands = count_bands(findings)
    import importlib.util
    pdf_available = importlib.util.find_spec("weasyprint") is not None
    return _render(
        request, "scan_detail.html",
        {
            "scan": scan,
            "findings": findings,
            "bands": bands,
            "surfaces": surface_breakdown(findings),
            "surface_order": SURFACE_ORDER,
            "surface_labels": SURFACE_LABELS,
            "readiness": readiness_score(bands),
            "pdf_available": pdf_available,
        },
    )


@router.get("/scans/{scan_id}/report/tech", response_class=HTMLResponse)
async def scan_report_tech(request: Request, scan_id: int) -> HTMLResponse:
    """HTML report (technical) — browser-printable, no weasyprint required."""
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    from pqcscan.renderers.pdf_technical import build_html_technical
    html = build_html_technical(repo, scan_id)
    return HTMLResponse(html)


@router.get("/scans/{scan_id}/report/exec_summary", response_class=HTMLResponse)
async def scan_report_exec_summary(request: Request, scan_id: int) -> HTMLResponse:
    """HTML report (executive summary) — browser-printable, no weasyprint required."""
    repo = request.app.state.repo
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    from pqcscan.renderers.pdf_executive import build_html_executive
    html = build_html_executive(repo, scan_id)
    return HTMLResponse(html)


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
