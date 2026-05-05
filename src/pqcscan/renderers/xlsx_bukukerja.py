"""renderers.xlsx_bukukerja — Malaysian BUKUKERJA workbook (NACSA Lampiran A).

Loads the bundled official template `templates/bukukerja-template.xlsx`
(8 sheets, including the static 5_RiskMatrix and 138-row 6_ProtocolCryptoMap
reference data) and populates the five dynamic sheets with rows derived
from the scan findings:

  0_Inventory      — Table 0: Initial Inventory for PQC Readiness (9 cols)
  1_SBOM           — Table 1: Software Bill of Materials (17 cols)
  2_CBOM           — Table 2: Cryptographic Bill of Materials (8 cols)
  3_RiskRegister   — Table 3: Risk Register (8 cols, BM headers)
  4_RiskAssessment — Table 4: Risk & Dependency Assessment (11 cols)

Static sheets `5_RiskMatrix`, `6_ProtocolCryptoMap`, `00_ReadMe` are left
intact so the workbook is a drop-in submission for NACSA Arahan KE No. 9
Borang Pelaksanaan Migrasi PQC. Headers in the template start at row 4;
data fills row 5+. We delete the example "Contoh:" rows shipped with the
template before populating.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from openpyxl import load_workbook
from openpyxl.styles import Alignment

from pqcscan.store.repo import Repo

_TEMPLATE_PATH = Path(__file__).parent / "templates" / "bukukerja-template.xlsx"

# pqcscan classification → BUKUKERJA Risk Matrix Impact (1-5).
_IMPACT_BY_CLASSIFICATION: dict[str, int] = {
    "sangat-tinggi": 5,
    "tinggi": 4,
    "sederhana": 3,
    "rendah": 2,
    "info": 1,
    "error": 1,
    "pqc-ready": 1,
}

# Probe family → Likelihood (1-5). Heuristic: live network/runtime crypto
# is more imminently exploitable than dormant code or SBOM listings.
_LIKELIHOOD_BY_FAMILY_PREFIX: dict[str, int] = {
    "net.": 5,        # network — live exploitable
    "host.": 4,       # host config — high likelihood
    "vpn.": 4,
    "app.": 4,
    "storage.": 3,
    "fs.": 3,
    "container.": 3,
    "code.": 3,       # source code — exploitable when deployed
    "sign.": 3,
    "dns_email.": 3,
    "sbom.": 2,       # SBOM listing — depends on actual usage
    "secrets.": 4,
    "aux.": 1,
    "pqc_meta.": 1,
}


def _likelihood_for(probe_id: str) -> int:
    pid = (probe_id or "").lower()
    for prefix, val in _LIKELIHOOD_BY_FAMILY_PREFIX.items():
        if pid.startswith(prefix):
            return val
    return 3


def _risk_level_label(score: int) -> str:
    """BUKUKERJA Risk Matrix interpretation (per Table 5)."""
    if score >= 20:
        return "Risiko Sangat Tinggi"
    if score >= 15:
        return "Risiko Tinggi"
    if score >= 10:
        return "Risiko Sederhana"
    if score >= 5:
        return "Risiko Rendah"
    return "Risiko Sangat Rendah"


def _migration_readiness(classification: str) -> str:
    """Map our classification to BUKUKERJA's Migration Readiness Level."""
    if classification == "pqc-ready":
        return "Tinggi"
    if classification == "rendah":
        return "Sederhana"
    if classification == "sederhana":
        return "Rendah"
    if classification in ("tinggi", "sangat-tinggi"):
        return "Sangat Rendah"
    return "Tidak Diketahui"


def _asset_type_for(probe_id: str) -> str:
    """First segment of probe.id — e.g. 'net' / 'host' / 'sbom'."""
    return (probe_id or "").split(".", 1)[0].upper() or "UNKNOWN"


def _asset_name_for(finding) -> str:
    """Best-guess identifier for an asset, drawn from the finding's evidence."""
    ev = finding.evidence or {}
    name = (
        ev.get("name")
        or ev.get("endpoint")
        or ev.get("host")
        or ev.get("path")
        or ev.get("dataset")
        or ev.get("device")
        or finding.probe_id
    )
    return str(name)


def _location_owner(finding) -> str:
    ev = finding.evidence or {}
    return (
        ev.get("location")
        or ev.get("owner")
        or ev.get("path")
        or ev.get("endpoint")
        or ""
    )


def _delete_example_rows(ws, header_row: int = 4) -> None:
    """Strip the 'Contoh:' placeholder rows shipped with the template."""
    while ws.max_row > header_row:
        ws.delete_rows(header_row + 1, ws.max_row - header_row)


def _wrap(cells) -> None:
    for c in cells:
        c.alignment = Alignment(wrap_text=True, vertical="top")


def render_xlsx_bukukerja(repo: Repo, scan_id: int, output_path: Path) -> Path:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)

    if not _TEMPLATE_PATH.is_file():
        raise FileNotFoundError(
            f"BUKUKERJA template missing at {_TEMPLATE_PATH}. "
            "Did the wheel build skip src/pqcscan/renderers/templates/?"
        )
    wb = load_workbook(_TEMPLATE_PATH)

    # ───────────  0_Inventory  ───────────
    inv = wb["0_Inventory"]
    _delete_example_rows(inv)
    # Group findings by (asset_type, asset_name) so the inventory is
    # asset-level rather than one-row-per-finding.
    grouped: dict[tuple[str, str], list] = defaultdict(list)
    for f in findings:
        grouped[(_asset_type_for(f.probe_id), str(_asset_name_for(f)))].append(f)
    for idx, ((asset_type, asset_name), fs) in enumerate(
        sorted(grouped.items()), start=1
    ):
        algos = sorted({
            f.algorithm for f in fs
            if f.algorithm and f.algorithm != "N/A"
        })
        sbom_present = (
            "Ya" if any(f.probe_id.startswith("sbom.") for f in fs) else "Tidak"
        )
        worst = max(
            (str(f.classification) for f in fs),
            key=lambda c: _IMPACT_BY_CLASSIFICATION.get(c, 0),
            default="info",
        )
        notes = "; ".join(sorted({f.title for f in fs[:3]}))[:300]
        inv.append([
            idx,
            asset_type,
            asset_name[:120],
            _location_owner(fs[0])[:120],
            "Ya" if algos else "Tidak",
            ", ".join(algos)[:200],
            sbom_present,
            _migration_readiness(worst),
            notes,
        ])
        _wrap(inv[inv.max_row])

    # ───────────  1_SBOM  ───────────
    sbom_ws = wb["1_SBOM"]
    _delete_example_rows(sbom_ws)
    sbom_findings = [f for f in findings if f.probe_id.startswith("sbom.")]
    for idx, f in enumerate(sbom_findings, start=1):
        ev = f.evidence or {}
        component = ev.get("name") or ""
        if ev.get("version"):
            component = f"{component} {ev['version']}".strip()
        sbom_ws.append([
            idx,
            str(_asset_name_for(f))[:120],     # System/Application
            ev.get("manager", ""),              # Purpose/Usage (manager as proxy)
            ev.get("url", ""),                  # URL
            "",                                 # Services Mode (manual)
            "",                                 # Target Customer (manual)
            component[:120],                    # Software Component
            "",                                 # Third-party Modules (manual)
            "",                                 # External APIs (manual)
            str(f.classification),              # Critical Level
            "",                                 # Data Category (manual)
            "",                                 # Currently in use? (manual)
            "",                                 # Developer (manual)
            ev.get("vendor", ""),               # Vendor's Name
            "",                                 # Has expertise? (manual)
            "",                                 # Has special budget? (manual)
            "",                                 # Link to CBOM (manual)
        ])
        _wrap(sbom_ws[sbom_ws.max_row])

    # ───────────  2_CBOM  ───────────
    cbom_ws = wb["2_CBOM"]
    _delete_example_rows(cbom_ws)
    cbom_findings = [
        f for f in findings
        if not f.probe_id.startswith("sbom.")
        and str(f.classification) != "info"
        and f.algorithm and f.algorithm != "N/A"
    ]
    for idx, f in enumerate(cbom_findings, start=1):
        ev = f.evidence or {}
        cbom_ws.append([
            f"CBOM #{idx}",                                              # # (CBOM)
            str(_asset_name_for(f))[:120],                               # System/Application
            f.probe_id.split(".", 2)[-1].replace("_", " ").title(),      # Cryptographic Function
            f.algorithm,                                                 # Algorithm Used
            ev.get("library", "") or ev.get("provider", ""),             # Library/Module
            ev.get("key_size") or ev.get("key_length", ""),              # Key Length
            f.title[:200],                                               # Purpose/Usage
            "Ya" if ev.get("crypto_agility") else "Tidak Diketahui",     # Crypto-Agility
        ])
        _wrap(cbom_ws[cbom_ws.max_row])

    # Risk-related sheets only emit findings classified high or above.
    risk_findings = [
        f for f in findings
        if str(f.classification) in ("sangat-tinggi", "tinggi", "sederhana")
    ]

    # ───────────  3_RiskRegister  ───────────
    risk_ws = wb["3_RiskRegister"]
    _delete_example_rows(risk_ws)
    for idx, f in enumerate(risk_findings, start=1):
        risk_ws.append([
            idx,                                                        # #
            str(_asset_name_for(f))[:120],                              # Nama Sistem
            _asset_type_for(f.probe_id),                                # Jenis Aset
            f.algorithm,                                                # Algoritma Kriptografi
            f.probe_id.split(".", 2)[-1].replace("_", " ").title(),     # Kegunaan
            str(f.classification),                                      # Tahap Kritikal
            f.title[:200],                                              # Risiko
            "",                                                         # Pemilik Risiko (manual)
        ])
        _wrap(risk_ws[risk_ws.max_row])

    # ───────────  4_RiskAssessment  ───────────
    assess_ws = wb["4_RiskAssessment"]
    _delete_example_rows(assess_ws)
    for idx, f in enumerate(risk_findings, start=1):
        impact = _IMPACT_BY_CLASSIFICATION.get(str(f.classification), 1)
        likelihood = _likelihood_for(f.probe_id)
        score = impact * likelihood
        assess_ws.append([
            idx,                                                        # #
            str(_asset_name_for(f))[:120],                              # Nama Sistem
            f.algorithm,                                                # Algoritma Kriptografi
            f.title[:200],                                              # Risiko
            "Sistem/aplikasi sedia ada tidak menyokong algoritma PQC",  # Punca Risiko
            impact,                                                     # Impak (1-5)
            likelihood,                                                 # Kemungkinan (1-5)
            score,                                                      # Skor Risiko
            _risk_level_label(score),                                   # Risk Level
            "",                                                         # Kawalan Sedia Ada (manual)
            "",                                                         # Mitigation Plan (manual)
        ])
        _wrap(assess_ws[assess_ws.max_row])

    # 00_ReadMe, 5_RiskMatrix, 6_ProtocolCryptoMap left intact.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(str(output_path))
    return output_path
