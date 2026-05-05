"""Minimal EN/MS translation table + cookie-based locale for the web UI.

We deliberately avoid babel/gettext: the UI surface is small (~30 strings)
and the bundled YAML compliance frameworks already carry their own
Bahasa-language notes (BUKUKERJA, MyKripto, NACSA), which the engine
surfaces verbatim.
"""
from __future__ import annotations

from fastapi import Request

LOCALE_COOKIE = "pqcscan_locale"
DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES = ("en", "ms")


LOCALES: dict[str, dict[str, str]] = {
    "en": {
        "nav.dashboard": "Dashboard",
        "nav.scans": "Scans",
        "nav.frameworks": "Frameworks",
        "nav.baselines": "Baselines",
        "nav.probes": "Probes",
        "nav.settings": "Settings",
        "lang.label": "Language",
        "lang.en": "EN",
        "lang.ms": "MS",
        "settings.title": "Settings",
        "settings.help": "Read-only system info. Edit pqcscan.daemon config or env vars to change values.",
        "settings.field.version": "Version",
        "settings.field.python": "Python",
        "settings.field.platform": "Platform",
        "settings.field.mode": "Privilege mode",
        "settings.field.db": "Database",
        "settings.field.caps": "Capabilities",
        "settings.field.probes": "Probes registered",
        "settings.field.frameworks": "Frameworks bundled",
        "settings.caps.none": "(no extra capabilities — running as user)",
        "scan.mark_baseline.heading": "Mark this scan as a baseline",
        "scan.mark_baseline.label": "Label",
        "scan.mark_baseline.button": "Mark as baseline",
        "dashboard.title": "Dashboard",
        "dashboard.scan_now": "Scan now",
        "dashboard.last_scan": "Last scan",
        "dashboard.no_scans": "No scans yet. Click “Scan now”.",
        "scans.title": "Scans",
        "scans.empty": "No scans yet.",
        "frameworks.title": "Compliance frameworks",
        "frameworks.bundled": "frameworks bundled.",
        "frameworks.col.framework": "Framework",
        "frameworks.col.title": "Title",
        "frameworks.col.rules": "Rules",
        "framework.col.clause": "Clause",
        "framework.col.match": "Match",
        "framework.col.verdict": "Verdict",
        "framework.col.note": "Note",
        "probes.title": "Probes",
        "probes.registered": "probes registered, grouped by family.",
        "probes.col.id": "Probe ID",
        "probes.col.tags": "Framework tags",
        "baselines.title": "Baselines",
        "baselines.help": ("A baseline freezes a scan as a reference point. "
                          "Compare any later scan against a baseline to see "
                          "what changed (added / removed findings)."),
        "baselines.col.label": "Label",
        "baselines.col.scan": "Scan",
        "baselines.col.created": "Created",
        "baselines.col.notes": "Notes",
        "baselines.empty": ("No baselines yet — mark a scan as baseline "
                           "from the scan detail page."),
        "baselines.diff.heading": "Diff against baseline",
        "baselines.diff.current": "Current scan",
        "baselines.diff.baseline": "Baseline",
        "baselines.diff.button": "Diff",
        "diff.added": "added",
        "diff.removed": "removed",
        "diff.common": "unchanged",
        "diff.no_added": "No new findings introduced since the baseline.",
        "diff.no_removed": "No findings disappeared since the baseline.",
    },
    "ms": {
        "nav.dashboard": "Papan Pemuka",
        "nav.scans": "Imbasan",
        "nav.frameworks": "Rangka Kerja",
        "nav.baselines": "Garis Dasar",
        "nav.probes": "Penyiasat",
        "nav.settings": "Tetapan",
        "lang.label": "Bahasa",
        "lang.en": "EN",
        "lang.ms": "MS",
        "settings.title": "Tetapan",
        "settings.help": "Maklumat sistem (baca sahaja). Edit konfigurasi pqcscan.daemon atau pemboleh ubah persekitaran untuk menukar nilai.",  # noqa: E501
        "settings.field.version": "Versi",
        "settings.field.python": "Python",
        "settings.field.platform": "Platform",
        "settings.field.mode": "Mod keistimewaan",
        "settings.field.db": "Pangkalan data",
        "settings.field.caps": "Keupayaan",
        "settings.field.probes": "Penyiasat didaftarkan",
        "settings.field.frameworks": "Rangka kerja disertakan",
        "settings.caps.none": "(tiada keupayaan tambahan — berjalan sebagai pengguna)",
        "scan.mark_baseline.heading": "Tandakan imbasan ini sebagai garis dasar",
        "scan.mark_baseline.label": "Label",
        "scan.mark_baseline.button": "Tandakan garis dasar",
        "dashboard.title": "Papan Pemuka",
        "dashboard.scan_now": "Imbas sekarang",
        "dashboard.last_scan": "Imbasan terakhir",
        "dashboard.no_scans": "Belum ada imbasan. Klik “Imbas sekarang”.",
        "scans.title": "Imbasan",
        "scans.empty": "Belum ada imbasan.",
        "frameworks.title": "Rangka kerja pematuhan",
        "frameworks.bundled": "rangka kerja disertakan.",
        "frameworks.col.framework": "Rangka Kerja",
        "frameworks.col.title": "Tajuk",
        "frameworks.col.rules": "Peraturan",
        "framework.col.clause": "Klausa",
        "framework.col.match": "Padanan",
        "framework.col.verdict": "Keputusan",
        "framework.col.note": "Nota",
        "probes.title": "Penyiasat",
        "probes.registered": "penyiasat didaftarkan, dikumpulkan mengikut keluarga.",
        "probes.col.id": "ID Penyiasat",
        "probes.col.tags": "Tag rangka kerja",
        "baselines.title": "Garis Dasar",
        "baselines.help": ("Garis dasar membekukan satu imbasan sebagai titik "
                          "rujukan. Bandingkan mana-mana imbasan kemudian "
                          "dengan garis dasar untuk melihat apa yang berubah "
                          "(penemuan ditambah / dibuang)."),
        "baselines.col.label": "Label",
        "baselines.col.scan": "Imbasan",
        "baselines.col.created": "Dicipta",
        "baselines.col.notes": "Nota",
        "baselines.empty": ("Belum ada garis dasar — tandakan imbasan "
                           "sebagai garis dasar dari halaman butiran imbasan."),
        "baselines.diff.heading": "Beza dengan garis dasar",
        "baselines.diff.current": "Imbasan semasa",
        "baselines.diff.baseline": "Garis dasar",
        "baselines.diff.button": "Beza",
        "diff.added": "ditambah",
        "diff.removed": "dibuang",
        "diff.common": "tidak berubah",
        "diff.no_added": "Tiada penemuan baru sejak garis dasar.",
        "diff.no_removed": "Tiada penemuan yang hilang sejak garis dasar.",
    },
}


def get_locale(request: Request) -> str:
    """Read the locale cookie; fall back to DEFAULT_LOCALE if absent/invalid."""
    cookie = request.cookies.get(LOCALE_COOKIE)
    if cookie in SUPPORTED_LOCALES:
        return cookie
    return DEFAULT_LOCALE


def t(key: str, locale: str = DEFAULT_LOCALE) -> str:
    """Translate a key. Falls back to EN, then to the key itself."""
    table = LOCALES.get(locale) or LOCALES[DEFAULT_LOCALE]
    return table.get(key) or LOCALES[DEFAULT_LOCALE].get(key) or key
