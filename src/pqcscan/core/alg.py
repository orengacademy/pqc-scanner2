from __future__ import annotations

import re

from pqcscan.core.types import Classification


_OID_MAP: dict[str, str] = {
    "1.2.840.113549.1.1.5": "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.3.101.112": "Ed25519",
    "1.3.6.1.4.1.2.267.7.4.4": "ML-DSA-44",
    "1.3.6.1.4.1.2.267.7.6.5": "ML-DSA-65",
}

_FRIENDLY_MAP: dict[str, str] = {
    "sha256withrsaencryption": "RSA-SHA256",
    "sha384withrsaencryption": "RSA-SHA384",
    "sha512withrsaencryption": "RSA-SHA512",
    "sha1withrsaencryption": "RSA-SHA1",
    "ecdsa-with-sha256": "ECDSA-SHA256",
    "ecdsa-with-sha384": "ECDSA-SHA384",
    "ed25519": "Ed25519",
    "id-ml-kem-512": "ML-KEM-512",
    "id-ml-kem-768": "ML-KEM-768",
    "id-ml-kem-1024": "ML-KEM-1024",
    "id-ml-dsa-44": "ML-DSA-44",
    "id-ml-dsa-65": "ML-DSA-65",
    "id-ml-dsa-87": "ML-DSA-87",
}


def normalise(s: str) -> str:
    """Return canonical algorithm name; unknown values are upper-cased."""
    if s in _OID_MAP:
        return _OID_MAP[s]
    key = s.lower().strip()
    if key in _FRIENDLY_MAP:
        return _FRIENDLY_MAP[key]
    return s.upper()


_RSA_RE = re.compile(r"^RSA-?(\d+)$", re.IGNORECASE)
_DH_RE = re.compile(r"^DH-?(\d+)$", re.IGNORECASE)


def classify(alg: str) -> Classification:
    """Map a normalised algorithm to a PQC threat classification."""
    a = normalise(alg).upper()

    pqc_ready_prefixes = (
        "ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "SPHINCS",
        "X25519MLKEM768", "P256+ML-KEM", "X448MLKEM",
    )
    if any(a.startswith(p.upper()) for p in pqc_ready_prefixes):
        return Classification.PQC_READY

    if a in {
        "MD5", "MD4", "MD2",
        "SHA-1", "SHA1",
        "RC4", "RC2",
        "DES", "3DES", "TRIPLEDES", "TDES",
        "DSA",
    }:
        return Classification.SANGAT_TINGGI

    if m := _RSA_RE.match(a):
        bits = int(m.group(1))
        if bits < 3072:
            return Classification.SANGAT_TINGGI
        return Classification.TINGGI

    if m := _DH_RE.match(a):
        bits = int(m.group(1))
        if bits < 3072:
            return Classification.SANGAT_TINGGI
        return Classification.TINGGI

    if a.startswith("ECDSA-") or a in {"ED25519"}:
        return Classification.TINGGI

    if a.startswith("AES-128-GCM") or a == "AES-128-GCM":
        return Classification.SEDERHANA
    if a.startswith("AES-128"):
        return Classification.TINGGI
    if a.startswith("AES-256"):
        return Classification.RENDAH

    if a in {"SHA-256", "SHA256"}:
        return Classification.SEDERHANA
    if a in {"SHA-384", "SHA384", "SHA-512", "SHA512"}:
        return Classification.RENDAH

    return Classification.INFO
