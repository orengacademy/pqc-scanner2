"""Structured PQC-replacement guidance for a classical algorithm.

`Finding.remediation` is a free-form dict any probe may populate (e.g. a
config snippet). This module adds a *typed* layer on top: given an algorithm
name it returns the NIST-standardised post-quantum replacement, the FIPS
standard that defines it, the migration deadline, and a one-line rationale.

The runner calls `enrich()` centrally so every stored finding carries this
guidance without each of the 147 probes having to duplicate the mapping. A
probe that already set `remediation["replacement"]` keeps its own value —
enrichment only fills gaps.
"""
from __future__ import annotations

from typing import Any

from pqcscan.core.alg import (
    hndl_exposed,
    is_key_establishment,
    migration_deadline,
    normalise,
)
from pqcscan.core.types import Classification, Finding

# Primitive → recommended PQC migration target. Signatures move to ML-DSA
# (FIPS 204) for general use; firmware / long-lived roots that need a
# conservative, hash-based option get SLH-DSA (FIPS 205). Key establishment
# moves to ML-KEM (FIPS 203), deployed as a hybrid with the incumbent curve
# so the channel stays at least as strong as today during transition.
_KEM_TARGET = {
    "replacement": "ML-KEM-768",
    "hybrid": "X25519MLKEM768",
    "standard": "FIPS 203",
    "kind": "key-establishment",
}
_SIG_TARGET = {
    "replacement": "ML-DSA-65",
    "alternative": "SLH-DSA-SHA2-192s (FIPS 205, hash-based, for firmware/roots)",
    "standard": "FIPS 204",
    "kind": "signature",
}


def _target_for(alg: str) -> dict[str, Any] | None:
    """Return the replacement descriptor for a classical `alg`, or None."""
    a = normalise(alg).upper()

    if is_key_establishment(alg):
        return dict(_KEM_TARGET)

    # Signature / identity primitives.
    if a.startswith(("RSA", "ECDSA", "ED25519", "ED448", "DSA", "SM2")):
        return dict(_SIG_TARGET)

    # Symmetric: no PQC replacement — double the key length (Grover).
    if a.startswith("AES-128") or a == "AES-128":
        return {
            "replacement": "AES-256",
            "standard": "FIPS 197",
            "kind": "symmetric",
            "note": "Grover halves the effective key length; use a 256-bit key.",
        }

    # Broken hashes → modern SHA-2/3 (not a quantum issue, but must go).
    if a in {"MD5", "MD4", "MD2", "SHA-1", "SHA1"}:
        return {
            "replacement": "SHA-256",
            "standard": "FIPS 180-4",
            "kind": "hash",
            "note": "Legacy hash is collision-broken; migrate before PQC work.",
        }
    return None


def suggest(alg: str, classification: Classification | None = None) -> dict[str, Any] | None:
    """Return a typed remediation descriptor for `alg`, or None when the
    algorithm is already quantum-safe / unclassifiable."""
    target = _target_for(alg)
    if target is None:
        return None
    deadline = migration_deadline(alg, classification)
    out: dict[str, Any] = {
        "current": normalise(alg),
        **target,
    }
    if deadline:
        out["deadline"] = deadline
    if hndl_exposed(alg):
        out["hndl"] = True
        out["rationale"] = (
            "Harvest-now-decrypt-later: traffic captured today is "
            "decryptable once a cryptographically-relevant quantum computer "
            "exists. Migrate key establishment first."
        )
    return out


def enrich(finding: Finding) -> Finding:
    """Fill `finding.remediation` with PQC-replacement guidance in place,
    without overwriting anything a probe already set. Returns the finding
    for chaining."""
    if finding.remediation.get("replacement"):
        return finding  # probe already provided a specific target
    if finding.classification in (
        Classification.PQC_READY,
        Classification.INFO,
        Classification.ERROR,
    ):
        return finding
    descriptor = suggest(finding.algorithm, finding.classification)
    if descriptor is not None:
        # Preserve probe-authored keys (e.g. a config snippet); add ours.
        merged = {**descriptor, **finding.remediation}
        finding.remediation = merged
    return finding
