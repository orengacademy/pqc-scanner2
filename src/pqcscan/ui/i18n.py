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
        # ── shared / common ──
        "common.status": "Status",
        "common.mode": "Mode",
        "common.started": "Started",
        "common.finished": "Finished",
        "common.view": "View",
        "common.all": "all",
        "common.close": "Close",
        "common.download": "Download",
        "common.findings": "findings",
        "common.scan": "scan",
        "common.generated": "generated",
        "common.history": "history",
        "common.tagline": "post-quantum readiness scanner",
        "common.theme_toggle": "Toggle light / dark theme",
        # ── readiness bands ──
        "band.green": "Green",
        "band.yellow": "Yellow",
        "band.red": "Red",
        "band.grey": "Grey",
        "band.ready": "ready",
        "band.upgradable": "upgradable",
        "band.blocker": "blocker",
        "band.unknown": "unknown",
        # ── dashboard body ──
        "dashboard.heading": "Post-Quantum Cryptography (PQC) Readiness",
        "dashboard.subtitle": "pqcscan  —  nist-aligned crypto posture assessment",
        "dashboard.about": "About",
        "dashboard.about_heading": "How to read this page.",
        "dashboard.about_eyebrow": "aegis-style traffic-light readiness",
        "dashboard.about_intro": ("Each finding is bucketed into a traffic-light band based on "
                                  "the algorithm in use, the probe family, and whether the host "
                                  "software has a PQC upgrade path."),
        "dashboard.band_green_desc": "PQC or hybrid PQC in use (ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768).",
        "dashboard.band_yellow_desc": "Classical crypto today, but the software / vendor supports a PQC upgrade.",
        "dashboard.band_red_desc": "Classical crypto with <em>no</em> PQC roadmap. Highest risk.",
        "dashboard.band_grey_desc": "Not yet scanned, unreachable, or purely informational.",
        "dashboard.about_footer": ("Hover any algorithm in the findings list for a plain-English "
                                   "explanation. Mappings: NIST IR 8547, NIST FIPS 203/204/205, "
                                   "MyKripto, BUKUKERJA, NACSA."),
        "dashboard.org_readiness": "Organisational Readiness",
        "dashboard.no_scan_yet": "no scan yet",
        "dashboard.readiness_score": "readiness score",
        "dashboard.download_pdf": "Download PDF report",
        "dashboard.risk_assessment": "Risk Assessment",
        "dashboard.view_scan": "View scan",
        "dashboard.rate_limit": "manual rescans rate-limited to 1 / 10 min",
        "dashboard.surface_breakdown": "Breakdown by Crypto Surface",
        "dashboard.readiness_trend": "Readiness Trend",
        "dashboard.trend_a": "last",
        "dashboard.trend_b": "scans · higher is better",
        "dashboard.recent_scans": "Recent Scans",
        # ── scan form ──
        "scanform.target_label": "Network target (optional)",
        "scanform.paths_label": "Filesystem paths (optional, comma-separated)",
        "scanform.run": "Run scan",
        "scanform.help": ("Leave blank to scan the local host. A network target activates the "
                          "TLS/STARTTLS probes; paths activate certificate/key/code probes."),
        # ── NACSA phases ──
        "nacsa.heading": "NACSA Arahan KE No. 9 — Migration Phases",
        "nacsa.active": "active",
        "nacsa.done": "done",
        "nacsa.submission_via": "Submission via",
        "nacsa.coordinated": ("coordinated by PTPKM under NACSA. "
                              "3-month window from CE NACSA notice."),
        # ── scans list ──
        "scans.recorded": "scans recorded",
        # ── scan detail ──
        "scan.detail": "scan detail",
        "scan.readiness": "readiness",
        "scan.mode_word": "mode",
        "scan.started_word": "started",
        "scan.finished_word": "finished",
        "scan.findings_title": "Asset Inventory & Findings",
        "scan.scanning": "scanning",
        "scan.search_findings": "Search findings",
        "scan.filter_placeholder": "Filter findings…",
        "scan.running_hint": ("Scan is running — findings will appear here as "
                              "probes complete."),
        "scan.no_findings": "No findings recorded for this scan.",
        "scan.no_match": "No findings match your filter.",
        # ── band filter ──
        "filter.aria": "Filter findings by readiness band",
        "filter.all": "All",
        # ── export bar ──
        "export.title": "Export",
        "export.formats": "5 formats",
        "export.pdf_tech": "Technical PDF",
        "export.pdf_exec": "Executive PDF",
        "export.workbook": "Workbook",
        "export.engineer_grade": "engineer-grade",
        "export.board_summary": "board summary",
        "export.html_print": "HTML — browser Print to PDF",
        "export.nacsa_workbook": "NACSA workbook",
        "export.generic_xlsx": "generic XLSX",
        # ── remediation chips ──
        "remediation.migrate_to": "migrate to",
        "remediation.by": "by",
        "remediation.hndl_title": "Harvest-now-decrypt-later exposure",
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
        # ── shared / common ──
        "common.status": "Status",
        "common.mode": "Mod",
        "common.started": "Dimulakan",
        "common.finished": "Selesai",
        "common.view": "Lihat",
        "common.all": "semua",
        "common.close": "Tutup",
        "common.download": "Muat turun",
        "common.findings": "penemuan",
        "common.scan": "imbasan",
        "common.generated": "dijana",
        "common.history": "sejarah",
        "common.tagline": "pengimbas kesediaan pasca-kuantum",
        "common.theme_toggle": "Togol tema terang / gelap",
        # ── readiness bands ──
        "band.green": "Hijau",
        "band.yellow": "Kuning",
        "band.red": "Merah",
        "band.grey": "Kelabu",
        "band.ready": "sedia",
        "band.upgradable": "boleh naik taraf",
        "band.blocker": "penghalang",
        "band.unknown": "tidak diketahui",
        # ── dashboard body ──
        "dashboard.heading": "Kesediaan Kriptografi Pasca-Kuantum (PQC)",
        "dashboard.subtitle": "pqcscan  —  penilaian postur kripto sejajar-nist",
        "dashboard.about": "Perihal",
        "dashboard.about_heading": "Cara membaca halaman ini.",
        "dashboard.about_eyebrow": "kesediaan lampu-isyarat gaya-aegis",
        "dashboard.about_intro": ("Setiap penemuan dikelaskan ke dalam jalur lampu-isyarat "
                                  "berdasarkan algoritma yang digunakan, keluarga penyiasat, dan "
                                  "sama ada perisian hos mempunyai laluan naik taraf PQC."),
        "dashboard.band_green_desc": "PQC atau PQC hibrid digunakan (ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768).",
        "dashboard.band_yellow_desc": "Kripto klasik hari ini, tetapi perisian / vendor menyokong naik taraf PQC.",
        "dashboard.band_red_desc": "Kripto klasik <em>tanpa</em> pelan hala tuju PQC. Risiko tertinggi.",
        "dashboard.band_grey_desc": "Belum diimbas, tidak dapat dicapai, atau semata-mata bermaklumat.",
        "dashboard.about_footer": ("Tuding pada mana-mana algoritma dalam senarai penemuan untuk "
                                   "penjelasan ringkas. Pemetaan: NIST IR 8547, NIST FIPS "
                                   "203/204/205, MyKripto, BUKUKERJA, NACSA."),
        "dashboard.org_readiness": "Kesediaan Organisasi",
        "dashboard.no_scan_yet": "belum ada imbasan",
        "dashboard.readiness_score": "skor kesediaan",
        "dashboard.download_pdf": "Muat turun laporan PDF",
        "dashboard.risk_assessment": "Penilaian Risiko",
        "dashboard.view_scan": "Lihat imbasan",
        "dashboard.rate_limit": "imbas semula manual dihadkan kepada 1 / 10 min",
        "dashboard.surface_breakdown": "Pecahan mengikut Permukaan Kripto",
        "dashboard.readiness_trend": "Trend Kesediaan",
        "dashboard.trend_a": "terakhir",
        "dashboard.trend_b": "imbasan · lebih tinggi lebih baik",
        "dashboard.recent_scans": "Imbasan Terkini",
        # ── scan form ──
        "scanform.target_label": "Sasaran rangkaian (pilihan)",
        "scanform.paths_label": "Laluan sistem fail (pilihan, dipisah koma)",
        "scanform.run": "Jalankan imbasan",
        "scanform.help": ("Biarkan kosong untuk mengimbas hos tempatan. Sasaran rangkaian "
                          "mengaktifkan penyiasat TLS/STARTTLS; laluan mengaktifkan penyiasat "
                          "sijil/kunci/kod."),
        # ── NACSA phases ──
        "nacsa.heading": "NACSA Arahan KE No. 9 — Fasa Migrasi",
        "nacsa.active": "aktif",
        "nacsa.done": "selesai",
        "nacsa.submission_via": "Penyerahan melalui",
        "nacsa.coordinated": ("diselaraskan oleh PTPKM di bawah NACSA. "
                              "Tempoh 3 bulan dari notis CE NACSA."),
        # ── scans list ──
        "scans.recorded": "imbasan direkodkan",
        # ── scan detail ──
        "scan.detail": "butiran imbasan",
        "scan.readiness": "kesediaan",
        "scan.mode_word": "mod",
        "scan.started_word": "dimulakan",
        "scan.finished_word": "selesai",
        "scan.findings_title": "Inventori Aset & Penemuan",
        "scan.scanning": "mengimbas",
        "scan.search_findings": "Cari penemuan",
        "scan.filter_placeholder": "Tapis penemuan…",
        "scan.running_hint": ("Imbasan sedang berjalan — penemuan akan muncul di sini "
                              "apabila penyiasat selesai."),
        "scan.no_findings": "Tiada penemuan direkodkan untuk imbasan ini.",
        "scan.no_match": "Tiada penemuan sepadan dengan tapisan anda.",
        # ── band filter ──
        "filter.aria": "Tapis penemuan mengikut jalur kesediaan",
        "filter.all": "Semua",
        # ── export bar ──
        "export.title": "Eksport",
        "export.formats": "5 format",
        "export.pdf_tech": "PDF Teknikal",
        "export.pdf_exec": "PDF Eksekutif",
        "export.workbook": "Buku Kerja",
        "export.engineer_grade": "gred jurutera",
        "export.board_summary": "ringkasan lembaga",
        "export.html_print": "HTML — Cetak ke PDF pelayar",
        "export.nacsa_workbook": "buku kerja NACSA",
        "export.generic_xlsx": "XLSX generik",
        # ── remediation chips ──
        "remediation.migrate_to": "migrasi ke",
        "remediation.by": "menjelang",
        "remediation.hndl_title": "Pendedahan tuai-sekarang-nyahsulit-kemudian",
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
