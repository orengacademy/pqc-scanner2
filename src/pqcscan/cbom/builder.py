from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pqcscan import __version__
from pqcscan.store.repo import Repo

# CycloneDX 1.7 schema identifier (matches the `$id` of bom-1.7.schema.json).
_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.7.schema.json"
_SPEC_VERSION = "1.7"

# Map free-text curve tokens onto the standardized CycloneDX 1.7 elliptic-curve
# enum (cryptography-defs.schema.json#/definitions/ellipticCurvesEnum). The 1.7
# spec deprecates the free-text `curve` field in favour of the namespaced
# `ellipticCurve` enum, so we emit the latter. Ordered most-specific first:
# tokens like "secp256r1" and "nistp256" contain the substring "P256", so the
# broad NIST short-names must be matched last.
_CURVE_ENUM: tuple[tuple[str, str], ...] = (
    # brainpool (r1/t1 across all standard sizes)
    ("BRAINPOOLP160R1", "brainpool/brainpoolP160r1"),
    ("BRAINPOOLP160T1", "brainpool/brainpoolP160t1"),
    ("BRAINPOOLP192R1", "brainpool/brainpoolP192r1"),
    ("BRAINPOOLP192T1", "brainpool/brainpoolP192t1"),
    ("BRAINPOOLP224R1", "brainpool/brainpoolP224r1"),
    ("BRAINPOOLP224T1", "brainpool/brainpoolP224t1"),
    ("BRAINPOOLP256R1", "brainpool/brainpoolP256r1"),
    ("BRAINPOOLP256T1", "brainpool/brainpoolP256t1"),
    ("BRAINPOOLP320R1", "brainpool/brainpoolP320r1"),
    ("BRAINPOOLP320T1", "brainpool/brainpoolP320t1"),
    ("BRAINPOOLP384R1", "brainpool/brainpoolP384r1"),
    ("BRAINPOOLP384T1", "brainpool/brainpoolP384t1"),
    ("BRAINPOOLP512R1", "brainpool/brainpoolP512r1"),
    ("BRAINPOOLP512T1", "brainpool/brainpoolP512t1"),
    # ANSI X9.62 / SECG / NIST long names (specific, contain "P256" etc.)
    ("PRIME256V1", "x962/prime256v1"),
    ("SECP256K1", "secg/secp256k1"),
    ("SECP256R1", "secg/secp256r1"),
    ("SECP384R1", "secg/secp384r1"),
    ("SECP521R1", "secg/secp521r1"),
    ("NISTP256", "nist/P-256"),
    ("NISTP384", "nist/P-384"),
    ("NISTP521", "nist/P-521"),
    # Edwards / Montgomery curves
    ("CURVE25519", "other/Curve25519"),
    ("CURVE448", "other/Curve448"),
    ("ED25519", "other/Ed25519"),
    ("ED448", "other/Ed448"),
    ("X25519", "other/Curve25519"),
    ("X448", "other/Curve448"),
    # NIST short names last (substring of the SECG/x962 names above)
    ("P-256", "nist/P-256"),
    ("P256", "nist/P-256"),
    ("P-384", "nist/P-384"),
    ("P384", "nist/P-384"),
    ("P-521", "nist/P-521"),
    ("P521", "nist/P-521"),
)


def build_cbom(repo: Repo, scan_id: int) -> dict[str, Any]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)

    components: list[dict[str, Any]] = []
    for f in findings:
        if f.algorithm == "N/A":
            continue
        ev = f.evidence or {}
        confidence = ev.get("confidence", "high")
        algo_props: dict[str, Any] = {
            "primitive": _primitive_for(f.algorithm),
        }
        family = _algorithm_family_for(f.algorithm)
        if family is not None:
            algo_props["algorithmFamily"] = family
        algo_props["parameterSetIdentifier"] = f.algorithm
        curve = _elliptic_curve_for(f.algorithm, ev)
        if curve is not None:
            algo_props["ellipticCurve"] = curve
        algo_props["executionEnvironment"] = "software-plain-ram"
        algo_props["nistQuantumSecurityLevel"] = _nist_level_for(f.classification)

        comp: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": f"finding-{f.id}",
            "name": f.algorithm,
            "description": f.title,
            "cryptoProperties": {
                "assetType": _asset_type_for(f.probe_id),
                "algorithmProperties": algo_props,
            },
            # Provenance: detection confidence + probe, so a downstream CBOM
            # consumer can triage probabilistic (regex/name) detections.
            "properties": [
                {"name": "pqcscan:confidence", "value": confidence},
                {"name": "pqcscan:probe", "value": f.probe_id},
            ],
        }
        path = ev.get("path") or ev.get("file")
        if isinstance(path, str) and path:
            comp["evidence"] = {"occurrences": [{"location": path}]}
        components.append(comp)

    return {
        "$schema": _SCHEMA_URL,
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [
                {"vendor": "pqcscan", "name": "pqcscan", "version": __version__}
            ],
            "component": {
                "type": "device",
                "name": scan.host_fingerprint or "host",
                "bom-ref": f"host-scan-{scan_id}",
            },
        },
        "components": components,
    }


def _asset_type_for(probe_id: str) -> str:
    if probe_id.startswith("net."):
        return "protocol"
    if probe_id.startswith("fs.cert"):
        return "certificate"
    if probe_id.startswith("fs.privkey") or probe_id.endswith(".privkey"):
        return "key"
    return "algorithm"


def _primitive_for(algorithm: str) -> str:
    # Values MUST come from the CycloneDX 1.7 `primitive` enum. Note the earlier
    # 1.6 emitter used "cipher"/"key-agreement", which are NOT members of the
    # enum in either 1.6 or 1.7 (the valid tokens are "block-cipher"/
    # "stream-cipher" and "key-agree"); those are corrected here.
    a = algorithm.upper()
    if a.startswith(("ML-KEM", "X25519MLKEM", "KYBER")):
        return "kem"
    if a.startswith(("RSA", "ECDSA", "DSA", "ED25519", "ED448",
                     "ML-DSA", "SLH-DSA", "FALCON")):
        return "signature"
    if a.startswith("AES"):
        return "block-cipher"
    if a.startswith("CHACHA"):
        return "stream-cipher"
    if a.startswith(("SHA", "MD")):
        return "hash"
    if a.startswith(("X25519", "X448", "ECDH", "DH")):
        return "key-agree"
    return "other"


def _algorithm_family_for(algorithm: str) -> str | None:
    # Values MUST come from the CycloneDX 1.7 `algorithmFamily` enum
    # (cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum), which
    # is new in 1.7. We only assign a family when the mapping is unambiguous and
    # a matching enum member exists; otherwise we omit the field rather than
    # fabricate one. Notably there is no generic "RSA" family member (only the
    # padded schemes RSAES-*/RSASSA-*), and no "Falcon"/"FN-DSA" member, so
    # those are intentionally left unmapped.
    a = algorithm.upper()
    if a.startswith("ECDSA"):
        return "ECDSA"
    if a.startswith("ECDH"):
        return "ECDH"
    if a.startswith(("ED25519", "ED448")):
        return "EdDSA"
    if a.startswith(("X25519", "X448")):
        # X25519/X448 are ECDH key-agreement functions over Curve25519/448.
        return "ECDH"
    if a.startswith("ML-KEM"):
        return "ML-KEM"
    if a.startswith("ML-DSA"):
        return "ML-DSA"
    if a.startswith("SLH-DSA"):
        return "SLH-DSA"
    if a.startswith("AES"):
        return "AES"
    if a.startswith("CHACHA"):
        return "ChaCha20"
    if a.startswith(("SHA-3", "SHA3")):
        return "SHA-3"
    if a.startswith(("SHA-1", "SHA1")):
        return "SHA-1"
    if a.startswith("SHA"):
        return "SHA-2"
    if a.startswith("3DES"):
        return "3DES"
    if a.startswith("DES"):
        return "DES"
    if a.startswith("DSA"):
        return "DSA"
    if a.startswith("DH"):
        return "FFDH"
    return None


def _elliptic_curve_for(algorithm: str, evidence: dict[str, Any]) -> str | None:
    # Resolve the standardized 1.7 elliptic-curve enum value. Prefer an explicit
    # curve token from probe evidence (e.g. JWKS "crv"), then fall back to the
    # algorithm string (e.g. "ECDSA-P256", "EC-Curve25519").
    tokens: list[str] = []
    for key in ("curve", "crv", "ec_curve", "group"):
        val = evidence.get(key)
        if isinstance(val, str) and val:
            tokens.append(val)
    tokens.append(algorithm)
    for token in tokens:
        upper = token.upper()
        for needle, enum_value in _CURVE_ENUM:
            if needle in upper:
                return enum_value
    return None


def _nist_level_for(classification: str) -> int:
    return {
        "pqc-ready": 3,
        "rendah": 2,
        "sederhana": 1,
        "tinggi": 0,
        "sangat-tinggi": 0,
        "info": 0,
        "error": 0,
    }.get(classification, 0)
