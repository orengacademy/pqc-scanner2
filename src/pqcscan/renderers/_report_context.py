"""Shared context builder for the technical + executive reports.

Both the HTML (browser Print-to-PDF; the only path available in the frozen
binary) and the WeasyPrint PDF renderers consume this, so the two never drift.
Everything here is pure computation over the SQLite store — no I/O beyond the
repo reads.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import date
from typing import Any

from pqcscan import __version__
from pqcscan.core.agility import score_findings as agility_score
from pqcscan.core.bands import (
    SURFACE_ORDER,
    classify_band,
    count_bands,
    readiness_score,
    surface_breakdown,
)
from pqcscan.core.exposure import build_register, tier_counts
from pqcscan.core.migration_score import score_findings
from pqcscan.core.mosca import MoscaInputs, assess, summary_lines
from pqcscan.core.parity import is_drift
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


def _label_years(labels: dict[str, str], key: str) -> float | None:
    """Parse one agent-supplied label as years: finite, > 0, <= 200, else None."""
    try:
        v = float(labels[key])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    return v if math.isfinite(v) and 0 < v <= 200 else None


def mosca_from_labels(labels: dict[str, str]) -> MoscaInputs | None:
    """Mosca inputs from host labels ``data_lifetime`` / ``migration_years`` / ``threat_years`` (years).

    Labels are untrusted strings: bad values are ignored, never raised. Without a
    valid ``data_lifetime`` there is nothing to anchor on, so the result is None.
    """
    x = _label_years(labels, "data_lifetime")
    if x is None:
        return None
    return MoscaInputs(
        data_lifetime_years=x,
        migration_years=_label_years(labels, "migration_years") or 5.0,
        threat_years=_label_years(labels, "threat_years") or 10.0,
    )


def _mosca_context(
    findings: list[Any], lang: str, mosca_inputs: MoscaInputs | None, source: str | None = None
) -> dict[str, Any]:
    """Build the ``"mosca"`` context entry (Mosca X+Y>Z shelf-life analysis).

    When ``mosca_inputs`` is None a default set is used so the calculator always
    renders; ``assumed`` flags that so the template can label it an assumption.
    ``vulnerable`` counts red+yellow findings (classical crypto still in use).
    """
    assumed = mosca_inputs is None
    inputs = mosca_inputs or MoscaInputs(data_lifetime_years=10.0)
    result = assess(inputs)
    vulnerable = sum(1 for f in findings if classify_band(f) in ("red", "yellow"))
    lines = summary_lines(result, vulnerable_count=vulnerable)
    ctx = result.as_dict()
    ctx.update(
        assumed=assumed,
        source=source or ("default" if assumed else "explicit"),
        vulnerable=vulnerable,
        summary=lines.get(lang) or lines["en"],
        summary_en=lines["en"],
        summary_ms=lines["ms"],
    )
    return ctx


def build_report_context(
    repo: Repo,
    scan_id: int,
    lang: str = "en",
    mosca_inputs: MoscaInputs | None = None,
) -> dict[str, Any]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    host = repo.get_host(scan.host_id) if scan.host_id else None
    labels = dict(host.labels or {}) if host else {}
    source = None
    if mosca_inputs is None:
        mosca_inputs = mosca_from_labels(labels)
        source = "labels" if mosca_inputs else "default"
    findings = [f for f in repo.list_findings(scan_id) if not is_drift(f)]   # drift rows are markers, not findings
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

    migration_readiness = asdict(score_findings(findings))
    agility = asdict(agility_score(findings))
    register = build_register(findings)
    exposure = {
        "rows": [asdict(r) for r in register[:20]],
        "tier_counts": tier_counts(register),
        "total": len(register),
    }

    priority = _priority_groups(findings)
    hndl_count = sum(
        1 for f in findings if (f.remediation or {}).get("hndl")
    )
    low_confidence_count = sum(
        1 for f in findings if (f.evidence or {}).get("confidence") == "low"
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
        "migration_readiness": migration_readiness,
        "agility": agility,
        "exposure": exposure,
        "mosca": _mosca_context(findings, lang, mosca_inputs, source),
        "host_labels": labels,
        "fw_summary": {k: dict(v) for k, v in fw_summary.items()},
        "priority": priority,
        "hndl_count": hndl_count,
        "low_confidence_count": low_confidence_count,
        "top_findings": top_findings,
        "crit_probes": crit_probes,
        "total_findings": len(findings),
        "total_framework_views": len(framework_views),
        "band_of": classify_band,
        "nacsa_phases": _NACSA_PHASES,
        "nacsa_current": _current_phase(today),
        "generated_on": today.isoformat(),
    }
