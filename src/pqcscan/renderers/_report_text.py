"""Bilingual (English + Bahasa Melayu) strings for the PDF/HTML reports.

Kept separate from the web UI's `ui/i18n.py` so the reporting layer has no
dependency on FastAPI/request plumbing and can be rendered head-less (CLI,
frozen binary, cron). Technical acronyms (PQC, TLS, ML-KEM, HNDL, NIST,
FIPS, CNSA, NACSA…) are intentionally left untranslated in both locales.
"""
from __future__ import annotations

from collections.abc import Callable

_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        # Document chrome
        "tech.doc_title": "Technical Scan Report",
        "exec.doc_title": "Executive Summary",
        "report.subtitle": "Post-Quantum Cryptography Readiness Assessment",
        "report.scan": "Scan",
        "report.generated": "Generated",
        "report.started": "started",
        "report.finished": "finished",
        "report.mode": "mode",
        "report.status": "status",
        "report.host": "host",
        "report.target": "target",
        "report.confidential": "Confidential — cryptographic posture assessment",
        "report.toc": "Contents",
        # Section headings
        "sec.summary": "Executive summary",
        "sec.readiness": "Readiness overview",
        "sec.surfaces": "Breakdown by cryptographic surface",
        "sec.priority": "Priority remediation",
        "sec.compliance": "Compliance verdicts by framework",
        "sec.timeline": "Migration timeline",
        "sec.findings": "Detailed findings",
        "sec.top": "Top priority findings",
        "sec.where": "Where to start",
        # Readiness / bands
        "readiness.score": "Readiness score",
        "readiness.of100": "out of 100",
        "band.green": "PQC-ready",
        "band.yellow": "Upgradable",
        "band.red": "Blocker",
        "band.grey": "Informational",
        "band.green.desc": "Post-quantum or hybrid-PQC algorithms already in use.",
        "band.yellow.desc": "Classical crypto today, with a supported PQC upgrade path.",
        "band.red.desc": "Classical crypto with no PQC path — highest priority.",
        "band.grey.desc": "Unscanned, unreachable, or purely informational.",
        # Classifications
        "cls.sangat-tinggi": "Very high",
        "cls.tinggi": "High",
        "cls.sederhana": "Medium",
        "cls.rendah": "Low",
        "cls.pqc-ready": "PQC-ready",
        "cls.info": "Informational",
        "cls.error": "Error",
        # Findings table
        "col.severity": "Severity",
        "col.classification": "Risk",
        "col.algorithm": "Algorithm",
        "col.title": "Finding",
        "col.probe": "Probe",
        "col.framework": "Framework",
        "col.clause": "Clause",
        "col.verdict": "Verdict",
        "col.deadline": "Deadline",
        "col.count": "Assets",
        "col.target": "Migrate to",
        "col.standard": "Standard",
        "col.surface": "Surface",
        "col.total": "Total",
        "col.evidence": "Evidence",
        "col.remediation": "Remediation",
        # Surfaces
        "surface.tls": "TLS endpoints",
        "surface.ssh": "SSH",
        "surface.vpn": "VPN / IPsec / WireGuard",
        "surface.cert": "Certificates",
        "surface.code": "Code / SBOM",
        "surface.data": "Data-at-rest",
        # Verdicts
        "verdict.compliant": "Compliant",
        "verdict.non-compliant": "Non-compliant",
        "verdict.at-risk": "At risk",
        "verdict.advisory": "Advisory",
        "verdict.other": "Other",
        # Priority remediation
        "priority.intro": "Quantum-vulnerable assets grouped by their recommended "
                          "NIST post-quantum replacement, most-affected first. "
                          "Assets flagged HNDL (harvest-now-decrypt-later) should "
                          "move first — captured traffic is decryptable once a "
                          "quantum computer exists.",
        "priority.hndl": "HNDL",
        "priority.none": "No quantum-vulnerable assets requiring migration were found.",
        "where.intro": "The probes producing the most high/critical findings — "
                       "remediating these buys the most coverage:",
        "where.none": "No high or critical findings. Continue periodic scans to "
                      "maintain coverage.",
        "findings.none": "No findings recorded for this scan.",
        "compliance.none": "No framework verdicts were produced for this scan.",
        "findings_word": "findings",
        "assets_word": "assets",
        # Executive narrative pieces
        "exec.narrative": "This assessment identified {crit} very-high-risk and "
                          "{high} high-risk cryptographic assets that are "
                          "vulnerable to a future quantum computer, alongside "
                          "{ready} assets already using NIST post-quantum "
                          "algorithms (FIPS 203/204/205). The overall readiness "
                          "score is {score}/100.",
        "exec.hndl_call": "{n} asset(s) are harvest-now-decrypt-later exposed and "
                          "should be prioritised: traffic captured today is "
                          "decryptable retroactively once a quantum computer exists.",
        "timeline.now": "current phase",
        "footer": "Generated by pqcscan v{version}. This report reflects a "
                  "point-in-time cryptographic inventory and is not a guarantee "
                  "of compliance.",
    },
    "ms": {
        "tech.doc_title": "Laporan Imbasan Teknikal",
        "exec.doc_title": "Ringkasan Eksekutif",
        "report.subtitle": "Penilaian Kesediaan Kriptografi Pasca-Kuantum",
        "report.scan": "Imbasan",
        "report.generated": "Dijana",
        "report.started": "dimulakan",
        "report.finished": "selesai",
        "report.mode": "mod",
        "report.status": "status",
        "report.host": "hos",
        "report.target": "sasaran",
        "report.confidential": "Sulit — penilaian postur kriptografi",
        "report.toc": "Kandungan",
        "sec.summary": "Ringkasan eksekutif",
        "sec.readiness": "Gambaran kesediaan",
        "sec.surfaces": "Pecahan mengikut permukaan kriptografi",
        "sec.priority": "Pembaikan keutamaan",
        "sec.compliance": "Keputusan pematuhan mengikut rangka kerja",
        "sec.timeline": "Garis masa migrasi",
        "sec.findings": "Penemuan terperinci",
        "sec.top": "Penemuan keutamaan tertinggi",
        "sec.where": "Di mana hendak bermula",
        "readiness.score": "Skor kesediaan",
        "readiness.of100": "daripada 100",
        "band.green": "Sedia-PQC",
        "band.yellow": "Boleh naik taraf",
        "band.red": "Penghalang",
        "band.grey": "Maklumat",
        "band.green.desc": "Algoritma pasca-kuantum atau hibrid-PQC sudah digunakan.",
        "band.yellow.desc": "Kripto klasik hari ini, dengan laluan naik taraf PQC yang disokong.",
        "band.red.desc": "Kripto klasik tanpa laluan PQC — keutamaan tertinggi.",
        "band.grey.desc": "Belum diimbas, tidak dapat dicapai, atau bersifat maklumat.",
        "cls.sangat-tinggi": "Sangat tinggi",
        "cls.tinggi": "Tinggi",
        "cls.sederhana": "Sederhana",
        "cls.rendah": "Rendah",
        "cls.pqc-ready": "Sedia-PQC",
        "cls.info": "Maklumat",
        "cls.error": "Ralat",
        "col.severity": "Keterukan",
        "col.classification": "Risiko",
        "col.algorithm": "Algoritma",
        "col.title": "Penemuan",
        "col.probe": "Penyiasat",
        "col.framework": "Rangka Kerja",
        "col.clause": "Klausa",
        "col.verdict": "Keputusan",
        "col.deadline": "Tarikh akhir",
        "col.count": "Aset",
        "col.target": "Hijrah ke",
        "col.standard": "Piawaian",
        "col.surface": "Permukaan",
        "col.total": "Jumlah",
        "col.evidence": "Bukti",
        "col.remediation": "Pembaikan",
        "surface.tls": "Titik akhir TLS",
        "surface.ssh": "SSH",
        "surface.vpn": "VPN / IPsec / WireGuard",
        "surface.cert": "Sijil",
        "surface.code": "Kod / SBOM",
        "surface.data": "Data-dalam-simpanan",
        "verdict.compliant": "Patuh",
        "verdict.non-compliant": "Tidak patuh",
        "verdict.at-risk": "Berisiko",
        "verdict.advisory": "Nasihat",
        "verdict.other": "Lain-lain",
        "priority.intro": "Aset terdedah-kuantum dikumpulkan mengikut penggantian "
                          "pasca-kuantum NIST yang disyorkan, paling banyak "
                          "terjejas dahulu. Aset yang ditanda HNDL "
                          "(tuai-kini-nyahsulit-kemudian) perlu dihijrahkan dahulu "
                          "— trafik yang ditangkap boleh dinyahsulit sebaik sahaja "
                          "komputer kuantum wujud.",
        "priority.hndl": "HNDL",
        "priority.none": "Tiada aset terdedah-kuantum yang memerlukan migrasi ditemui.",
        "where.intro": "Penyiasat yang menghasilkan paling banyak penemuan "
                       "tinggi/kritikal — membaiki ini memberi liputan paling banyak:",
        "where.none": "Tiada penemuan tinggi atau kritikal. Teruskan imbasan "
                      "berkala untuk mengekalkan liputan.",
        "findings.none": "Tiada penemuan direkodkan untuk imbasan ini.",
        "compliance.none": "Tiada keputusan rangka kerja dihasilkan untuk imbasan ini.",
        "findings_word": "penemuan",
        "assets_word": "aset",
        "exec.narrative": "Penilaian ini mengenal pasti {crit} aset kriptografi "
                          "berisiko sangat tinggi dan {high} berisiko tinggi yang "
                          "terdedah kepada komputer kuantum masa depan, di samping "
                          "{ready} aset yang sudah menggunakan algoritma pasca-"
                          "kuantum NIST (FIPS 203/204/205). Skor kesediaan "
                          "keseluruhan ialah {score}/100.",
        "exec.hndl_call": "{n} aset terdedah tuai-kini-nyahsulit-kemudian dan perlu "
                          "diutamakan: trafik yang ditangkap hari ini boleh "
                          "dinyahsulit secara retroaktif sebaik komputer kuantum wujud.",
        "timeline.now": "fasa semasa",
        "footer": "Dijana oleh pqcscan v{version}. Laporan ini mencerminkan "
                  "inventori kriptografi pada satu titik masa dan bukan jaminan "
                  "pematuhan.",
    },
}


def report_translator(lang: str) -> Callable[[str], str]:
    """Return a `t(key)` function for `lang`, falling back to EN then the key."""
    table = _STRINGS.get(lang) or _STRINGS["en"]
    en = _STRINGS["en"]

    def t(key: str) -> str:
        return table.get(key) or en.get(key) or key

    return t
