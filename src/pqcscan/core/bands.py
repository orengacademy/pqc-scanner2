"""Traffic-light readiness classification.

Maps each Finding to one of four bands per the user spec:
- GREEN  — PQC or hybrid PQC in use
- YELLOW — classical crypto, but software supports PQC upgrade
- RED    — classical crypto, no PQC support
- GREY   — unknown / unscanned / observational

Each finding is also mapped to one of six crypto surfaces: TLS, SSH, VPN,
Certs, Code/SBOM, Data-at-rest. The dashboard renders this as a
"Breakdown by Crypto Surface" matrix.

Heuristic-based: refine probe-by-probe later if any classification feels
wrong. The split between RED and YELLOW asks "can the operator fix this
by flipping a config / upgrading the binary, or do they need a vendor
commit?". Code/SBOM/static-cert probes → RED. Runtime/config → YELLOW.
"""
from __future__ import annotations

# Algorithm-name fragments that indicate PQC or hybrid PQC primitives.
# Lowercase comparison; substring match.
PQC_ALGO_FRAGMENTS: tuple[str, ...] = (
    "ml-kem", "ml-dsa", "slh-dsa", "fn-dsa",
    "kyber", "dilithium", "falcon", "sphincs",
    "frodokem", "ntru", "saber", "classic-mceliece", "bike", "hqc",
    "xmss", "lms",
    # Hybrid kex naming (X25519MLKEM768, P256MLKEM768, etc.)
    "mlkem", "mldsa",
)


def classify_band(finding) -> str:
    """Return one of 'green' / 'yellow' / 'red' / 'grey' for a Finding."""
    classif = (
        finding.classification.value
        if hasattr(finding.classification, "value")
        else str(finding.classification)
    )
    algo = (finding.algorithm or "").lower().strip()
    pid = (finding.probe_id or "").lower()

    if classif == "pqc-ready" or any(p in algo for p in PQC_ALGO_FRAGMENTS):
        return "green"

    if classif in ("info", "error") or not algo or algo == "n/a":
        return "grey"

    if (
        pid.startswith(("code.", "sbom.", "fs.cert."))
        or pid == "trust.system_roots"
    ):
        return "red"

    return "yellow"


SURFACE_ORDER: tuple[str, ...] = ("tls", "ssh", "vpn", "cert", "code", "data")
SURFACE_LABELS: dict[str, str] = {
    "tls": "TLS endpoints",
    "ssh": "SSH",
    "vpn": "VPN / IPsec / WG",
    "cert": "Certificates",
    "code": "Code / SBOM",
    "data": "Data-at-rest",
}


def classify_surface(finding) -> str:
    """Bucket a finding into one of 6 crypto surfaces (or 'other')."""
    pid = (finding.probe_id or "").lower()

    if "tls" in pid or "starttls" in pid:
        return "tls"
    if pid.startswith("net.ssh") or ".ssh." in pid:
        return "ssh"
    if (
        pid.startswith("vpn.")
        or "wireguard" in pid
        or "tailscale" in pid
        or "openvpn" in pid
        or "ipsec" in pid
    ):
        return "vpn"
    if "cert" in pid or "x509" in pid or "trust" in pid or pid.startswith("sign."):
        return "cert"
    if pid.startswith(("code.", "sbom.")):
        return "code"
    if pid.startswith(("fs.", "storage.", "secrets.", "container.", "host.")):
        return "data"

    return "other"


def empty_band_counts() -> dict[str, int]:
    return {"green": 0, "yellow": 0, "red": 0, "grey": 0, "total": 0}


def count_bands(findings: list) -> dict[str, int]:
    """Aggregate findings into the 4 band buckets + total."""
    counts = empty_band_counts()
    for f in findings:
        band = classify_band(f)
        if band in counts:
            counts[band] += 1
        counts["total"] += 1
    return counts


def surface_breakdown(findings: list) -> dict[str, dict[str, int]]:
    """Return {surface: {green, yellow, red, grey, total}} for all 6 surfaces."""
    breakdown: dict[str, dict[str, int]] = {
        s: empty_band_counts() for s in SURFACE_ORDER
    }
    for f in findings:
        s = classify_surface(f)
        if s == "other":
            continue
        b = classify_band(f)
        if b in breakdown[s]:
            breakdown[s][b] += 1
        breakdown[s]["total"] += 1
    return breakdown


def readiness_score(counts: dict[str, int]) -> int:
    """Map a band-count dict to a 0-100 readiness score.

    Mirrors the AEGIS scoring intent: every red asset is a 0, every
    yellow is partial credit (50), every green is a 100, grey is
    excluded from the denominator. Total score is the weighted average.
    """
    weighted = counts["green"] * 100 + counts["yellow"] * 50
    denom = counts["green"] + counts["yellow"] + counts["red"]
    if denom == 0:
        return 0
    return round(weighted / denom)
