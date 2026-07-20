"""Shared context builder for the technical + executive reports.

Both the HTML (browser Print-to-PDF; the only path available in the frozen
binary) and the WeasyPrint PDF renderers consume this, so the two never drift.
Everything here is pure computation over the SQLite store — no I/O beyond the
repo reads.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from typing import Any

from pqcscan import __version__
from pqcscan.core.bands import (
    SURFACE_ORDER,
    classify_band,
    count_bands,
    readiness_score,
    surface_breakdown,
)
from pqcscan.renderers._report_text import report_translator
from pqcscan.store.repo import Repo

# NACSA Arahan KE No. 9, Lampiran A §C migration phases (bilingual names).
_NACSA_PHASES: list[dict[str, Any]] = [
    {"n": 1, "ms": "Persediaan", "en": "Assess",  "start": date(2025, 7, 1), "end": date(2025, 12, 31)},
    {"n": 2, "ms": "Pemilihan",  "en": "Select",  "start": date(2026, 1, 1), "end": date(2026, 6, 30)},
    {"n": 3, "ms": "Pengesahan", "en": "Validate","start": date(2026, 7, 1), "end": date(2026, 12, 31)},
    {"n": 4, "ms": "Pelaksanaan","en": "Deploy",  "start": date(2027, 1, 1), "end": date(2027, 6, 30)},
    {"n": 5, "ms": "Pemantauan", "en": "Monitor", "start": date(2027, 7, 1), "end": None},
]

_SEV_ORDER = {"crit": 4, "high": 3, "med": 2, "low": 1, "info": 0}


def _current_phase(today: date) -> int:
    for ph in _NACSA_PHASES:
        n = int(ph["n"])
        if today < ph["start"]:
            return max(1, n - 1)
        if ph["end"] is None or today <= ph["end"]:
            return n
    return 5


def _priority_groups(findings: list[Any]) -> list[dict[str, Any]]:
    """Group quantum-vulnerable findings by their recommended PQC replacement.

    Returns rows sorted HNDL-first, then by asset count desc — the order an
    operator should tackle migration in.
    """
    groups: dict[str, dict[str, Any]] = {}
    for f in findings:
        rem = f.remediation or {}
        target = rem.get("replacement")
        if not target:
            continue
        key = f"{target}|{rem.get('standard', '')}"
        g = groups.setdefault(key, {
            "target": target,
            "standard": rem.get("standard", ""),
            "deadline": rem.get("deadline"),
            "hndl": False,
            "count": 0,
            "algorithms": set(),
        })
        g["count"] += 1
        g["hndl"] = g["hndl"] or bool(rem.get("hndl"))
        if f.algorithm and f.algorithm != "N/A":
            g["algorithms"].add(f.algorithm)
        # Keep the earliest deadline seen for the group.
        d = rem.get("deadline")
        if d and (g["deadline"] is None or d < g["deadline"]):
            g["deadline"] = d

    rows = []
    for g in groups.values():
        g["algorithms"] = sorted(g["algorithms"])[:6]
        rows.append(g)
    rows.sort(key=lambda r: (not r["hndl"], -r["count"]))
    return rows


def build_report_context(repo: Repo, scan_id: int, lang: str = "en") -> dict[str, Any]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)
    framework_views = repo.list_framework_views(scan_id)

    verdicts_by_finding: dict[int, list[Any]] = defaultdict(list)
    for v in framework_views:
        verdicts_by_finding[v.finding_id].append(v)

    class_counts: Counter[str] = Counter(f.classification for f in findings)
    bands = count_bands(findings)
    surfaces = surface_breakdown(findings)
    score = readiness_score(bands)

    fw_summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for v in framework_views:
        fw_summary[v.framework][v.verdict] += 1

    priority = _priority_groups(findings)
    hndl_count = sum(
        1 for f in findings if (f.remediation or {}).get("hndl")
    )

    top_findings = sorted(
        (f for f in findings if f.severity in ("crit", "high")),
        key=lambda f: (-_SEV_ORDER.get(f.severity, 0), f.probe_id),
    )[:15]

    crit_probes = Counter(
        f.probe_id for f in findings if f.severity in ("crit", "high")
    ).most_common(6)

    # Findings sorted by severity for the detailed section.
    findings_sorted = sorted(
        findings, key=lambda f: (-_SEV_ORDER.get(f.severity, 0), f.probe_id)
    )

    today = date.today()
    return {
        "t": report_translator(lang),
        "lang": lang,
        "version": __version__,
        "scan": scan,
        "findings": findings_sorted,
        "verdicts_by_finding": verdicts_by_finding,
        "class_counts": dict(class_counts),
        "bands": bands,
        "surfaces": surfaces,
        "surface_order": SURFACE_ORDER,
        "readiness": score,
        "fw_summary": {k: dict(v) for k, v in fw_summary.items()},
        "priority": priority,
        "hndl_count": hndl_count,
        "top_findings": top_findings,
        "crit_probes": crit_probes,
        "total_findings": len(findings),
        "total_framework_views": len(framework_views),
        "band_of": classify_band,
        "nacsa_phases": _NACSA_PHASES,
        "nacsa_current": _current_phase(today),
        "generated_on": today.isoformat(),
    }
