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


# ───── Bahasa Malaysia helpers for BUKUKERJA Jadual 3 & 4 ─────

# Probe family → Jenis Aset (BM) per BUKUKERJA Jadual 3 column 3.
_JENIS_ASET_BY_FAMILY: dict[str, str] = {
    "net.": "Perkhidmatan Rangkaian",
    "host.": "Sistem Pengendalian / Konfigurasi Hos",
    "vpn.": "Perisian VPN",
    "storage.": "Storan",
    "fs.": "Sistem Fail / Sijil",
    "code.": "Kod Sumber",
    "sbom.": "Pakej Perisian",
    "container.": "Kontena / Imej Kontena",
    "app.": "Aplikasi",
    "sign.": "Sijil / Tandatangan Digital",
    "dns_email.": "DNS / E-mel",
    "secrets.": "Rahsia",
    "aux.": "Tambahan",
    "pqc_meta.": "Metadata PQC",
    "trust.": "Stor Sijil Akar Sistem",
}


def _jenis_aset(probe_id: str) -> str:
    """Return BUKUKERJA Jenis Aset label (BM) for a probe family."""
    pid = (probe_id or "").lower()
    for prefix, label in _JENIS_ASET_BY_FAMILY.items():
        if pid.startswith(prefix):
            return label
    return "Aset Lain"


def _kegunaan_kripto(probe_id: str, algorithm: str) -> str:
    """Map (probe, algorithm) to a Bahasa Malaysia crypto-function label
    for Jadual 3 column 5 (Kegunaan Algoritma Kriptografi)."""
    pid = (probe_id or "").lower()
    algo = (algorithm or "").upper()

    if "tls" in pid or "starttls" in pid or "https" in pid:
        return "Pertukaran Kunci & Pengesahan TLS"
    if pid.startswith("net.ssh") or ".ssh." in pid:
        return "Pertukaran Kunci & Pengesahan SSH"
    if pid.startswith("vpn.") or "wireguard" in pid or "openvpn" in pid:
        return "Pertukaran Kunci VPN"
    if "cert" in pid or "x509" in pid or "trust" in pid:
        return "Sijil & Tandatangan Digital"
    if pid.startswith("sign."):
        return "Tandatangan Kod / Imej"
    if pid.startswith(("storage.", "fs.fscrypt")):
        return "Penyulitan At-Rest"
    if pid.startswith("dns_email."):
        return "DNSSEC / DKIM"
    if pid.startswith(("code.", "sbom.")):
        return "Pelbagai (libraries)"
    if "kerberos" in pid:
        return "Pengesahan Kerberos"
    if "ldap" in pid:
        return "Pengesahan LDAP"
    if any(x in algo for x in ("RSA", "DSA", "ECDSA", "ED25519", "ED448")):
        return "Tandatangan Digital"
    if any(x in algo for x in ("DH", "ECDH", "X25519", "X448", "ML-KEM", "KYBER")):
        return "Pertukaran Kunci"
    if any(x in algo for x in ("AES", "CHACHA", "3DES", "DES", "RC4")):
        return "Penyulitan Simetri"
    if any(x in algo for x in ("SHA", "MD5", "BLAKE", "SHA3")):
        return "Hash / MAC"
    return "Pelbagai"


# Algorithm fragment → PQC migration recommendation (Pelan Mitigasi).
_PELAN_MITIGASI_RULES: list[tuple[tuple[str, ...], str]] = [
    (("ML-KEM", "MLKEM", "KYBER"),
     "Sudah selari PQC (ML-KEM, FIPS 203). Pemantauan berterusan."),
    (("ML-DSA", "MLDSA", "DILITHIUM"),
     "Sudah selari PQC (ML-DSA, FIPS 204). Pemantauan berterusan."),
    (("SLH-DSA", "SPHINCS"),
     "Sudah selari PQC (SLH-DSA, FIPS 205). Pemantauan berterusan."),
    (("RSA",),
     "Migrasi kepada ML-KEM-768 (KEM, FIPS 203) atau ML-DSA-65 "
     "(signature, FIPS 204). Pertimbangkan hybrid X25519MLKEM768 "
     "untuk fasa peralihan."),
    (("ECDSA", "ED25519", "ED448"),
     "Migrasi kepada ML-DSA-65 (FIPS 204) atau SLH-DSA-128s "
     "(FIPS 205). Pertimbangkan hybrid signature untuk peralihan."),
    (("ECDH", "X25519", "X448"),
     "Migrasi kepada ML-KEM-768 (FIPS 203) atau hybrid "
     "X25519MLKEM768 / P256MLKEM768."),
    (("DH-",),
     "Migrasi kepada ML-KEM-768 (FIPS 203). DH klasik dimansuhkan."),
    (("AES-128", "AES128"),
     "Naik taraf ke AES-256-GCM untuk hadapi serangan Grover "
     "(saiz kunci dua kali ganda)."),
    (("3DES", "DES-", "RC4", "BLOWFISH"),
     "Wajib gantikan dengan AES-256-GCM. Algoritma sudah dimansuhkan."),
    (("SHA-1", "SHA1"),
     "Migrasi ke SHA-256 atau SHA-3 (FIPS 180-4 / FIPS 202). "
     "SHA-1 sudah dimansuhkan."),
    (("MD5",),
     "Migrasi ke SHA-256 atau SHA-3. MD5 dilarang sepenuhnya."),
]


def _pelan_mitigasi(algorithm: str) -> str:
    """Return BUKUKERJA Pelan Mitigasi suggestion for Jadual 4 column 11."""
    algo = (algorithm or "").upper()
    if not algo or algo == "N/A":
        return "Daftar aset dalam Borang Pelaksanaan Migrasi PQC (Lampiran A, Jadual 0)."
    for fragments, plan in _PELAN_MITIGASI_RULES:
        if any(f in algo for f in fragments):
            return plan
    return "Rujuk Jadual 6 (Protocol Crypto Map) untuk algoritma pengganti PQC yang dicadangkan."


def _punca_risiko(probe_id: str, algorithm: str) -> str:
    """Map a finding to its Bahasa Malaysia root-cause label (Jadual 4 col 5)."""
    algo = (algorithm or "").upper()
    pid = (probe_id or "").lower()

    if any(x in algo for x in ("ML-KEM", "ML-DSA", "SLH-DSA", "MLKEM", "MLDSA")):
        return "Tiada — algoritma sudah selari PQC."
    if any(x in algo for x in ("RSA", "DSA", "ECDSA", "ECDH", "DH-", "X25519", "X448", "ED25519", "ED448")):
        return "Algoritma asimetri klasik — terdedah kepada serangan Shor pada CRQC."
    if any(x in algo for x in ("AES-128", "AES128", "3DES", "DES-", "RC4", "BLOWFISH")):
        return "Algoritma simetri lemah — dimansuhkan atau dilemahkan oleh Grover."
    if any(x in algo for x in ("SHA-1", "SHA1", "MD5", "MD4")):
        return "Algoritma cincang dimansuhkan — risiko pelanggaran/pra-imej."
    if pid.startswith("sbom."):
        return "Algoritma dikunci dalam pakej perisian — keperluan kemaskini vendor."
    if pid.startswith("code."):
        return "Algoritma terkunci dalam kod sumber — keperluan refactoring."
    if "cert" in pid or "x509" in pid or "trust" in pid:
        return "Sijil X.509 menggunakan kunci klasik — keperluan rotasi sijil PQC."
    return "Sistem/aplikasi sedia ada tidak menyokong algoritma PQC."


def _kawalan_sedia_ada(finding) -> str:
    """Detect compensating controls from a finding's evidence
    (Jadual 4 col 10 — Kawalan Sedia Ada)."""
    ev = finding.evidence or {}
    controls: list[str] = []
    # Probe might tag hybrid PQC kex if detected.
    if any(
        "MLKEM" in str(v).upper() or "KYBER" in str(v).upper() or "PQC" in str(v).upper()
        for v in ev.values()
    ):
        controls.append("Hybrid PQC kex dikesan")
    # FIPS validation tag.
    if any("FIPS" in str(v).upper() for v in ev.values()):
        controls.append("Modul FIPS 140")
    # Air-gapped / isolated network signal (heuristic).
    if ev.get("network") == "isolated" or ev.get("airgap"):
        controls.append("Rangkaian terasing")
    # Default: blank for the user to fill in.
    return "; ".join(controls)


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
            _jenis_aset(f.probe_id),                                    # Jenis Aset (BM)
            f.algorithm,                                                # Algoritma Kriptografi
            _kegunaan_kripto(f.probe_id, f.algorithm),                  # Kegunaan (BM)
            str(f.classification),                                      # Tahap Kritikal
            f.title[:200],                                              # Risiko (probe-emitted detail)
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
            _punca_risiko(f.probe_id, f.algorithm),                     # Punca Risiko (BM, dynamic)
            impact,                                                     # Impak (1-5)
            likelihood,                                                 # Kemungkinan (1-5)
            score,                                                      # Skor Risiko
            _risk_level_label(score),                                   # Risk Level
            _kawalan_sedia_ada(f),                                      # Kawalan Sedia Ada (auto-detected)
            _pelan_mitigasi(f.algorithm),                               # Mitigation Plan (algorithm-aware)
        ])
        _wrap(assess_ws[assess_ws.max_row])

    # 00_ReadMe, 5_RiskMatrix, 6_ProtocolCryptoMap left intact.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(str(output_path))
    return output_path
