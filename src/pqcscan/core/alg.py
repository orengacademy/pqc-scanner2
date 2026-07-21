from __future__ import annotations

import re

from pqcscan.core.types import Classification

# --- OID → friendly-name table ------------------------------------------
# Signature / key OIDs seen in X.509, PKCS#7/CMS, JOSE, and TLS. Kept
# explicit (not computed) so a new entry is a one-line, reviewable diff.
_OID_MAP: dict[str, str] = {
    # RSA (PKCS#1 v1.5)
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.113549.1.1.14": "RSA-SHA224",
    # RSASSA-PSS
    "1.2.840.113549.1.1.10": "RSA-PSS",
    # ECDSA
    "1.2.840.10045.4.1": "ECDSA-SHA1",
    "1.2.840.10045.4.3.1": "ECDSA-SHA224",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA512",
    # EdDSA
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # DSA
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10040.4.3": "DSA-SHA1",
    "2.16.840.1.101.3.4.3.2": "DSA-SHA256",
    # ML-DSA (FIPS 204) — NIST OIDs 2.16.840.1.101.3.4.3.{17,18,19}
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # ML-DSA — legacy pre-standard OQS arc (still seen in the wild)
    "1.3.6.1.4.1.2.267.7.4.4": "ML-DSA-44",
    "1.3.6.1.4.1.2.267.7.6.5": "ML-DSA-65",
    "1.3.6.1.4.1.2.267.7.8.7": "ML-DSA-87",
    # Composite / hybrid ML-DSA signatures (LAMPS
    # draft-ietf-lamps-pq-composite-sigs-19, IANA "SMI Security for PKIX
    # Algorithms" arc 1.3.6.1.5.5.7.6.{37..54}). A cert bearing one of these
    # has already migrated to hybrid PQC, so the readable name keeps the
    # "ML-DSA" token and lands in PQC_READY via _PQC_READY_PREFIXES.
    "1.3.6.1.5.5.7.6.37": "ML-DSA-44+RSA2048-PSS",
    "1.3.6.1.5.5.7.6.38": "ML-DSA-44+RSA2048-PKCS15",
    "1.3.6.1.5.5.7.6.39": "ML-DSA-44+Ed25519",
    "1.3.6.1.5.5.7.6.40": "ML-DSA-44+ECDSA-P256",
    "1.3.6.1.5.5.7.6.41": "ML-DSA-65+RSA3072-PSS",
    "1.3.6.1.5.5.7.6.42": "ML-DSA-65+RSA3072-PKCS15",
    "1.3.6.1.5.5.7.6.43": "ML-DSA-65+RSA4096-PSS",
    "1.3.6.1.5.5.7.6.44": "ML-DSA-65+RSA4096-PKCS15",
    "1.3.6.1.5.5.7.6.45": "ML-DSA-65+ECDSA-P256",
    "1.3.6.1.5.5.7.6.46": "ML-DSA-65+ECDSA-P384",
    "1.3.6.1.5.5.7.6.47": "ML-DSA-65+ECDSA-brainpoolP256r1",
    "1.3.6.1.5.5.7.6.48": "ML-DSA-65+Ed25519",
    "1.3.6.1.5.5.7.6.49": "ML-DSA-87+ECDSA-P384",
    "1.3.6.1.5.5.7.6.50": "ML-DSA-87+ECDSA-brainpoolP384r1",
    "1.3.6.1.5.5.7.6.51": "ML-DSA-87+Ed448",
    "1.3.6.1.5.5.7.6.52": "ML-DSA-87+RSA3072-PSS",
    "1.3.6.1.5.5.7.6.53": "ML-DSA-87+RSA4096-PSS",
    "1.3.6.1.5.5.7.6.54": "ML-DSA-87+ECDSA-P521",
    # SLH-DSA (FIPS 205) — NIST OIDs 2.16.840.1.101.3.4.3.{20..31}
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    # Pre-hash ("external-hash") variants — HashML-DSA (FIPS 204) and
    # HashSLH-DSA (FIPS 205), verified against the NIST CSOR arc .32-.46. A cert
    # signed in pre-hash mode carries one of these; they must classify PQC-ready
    # just like their pure counterparts.
    "2.16.840.1.101.3.4.3.32": "HashML-DSA-44",
    "2.16.840.1.101.3.4.3.33": "HashML-DSA-65",
    "2.16.840.1.101.3.4.3.34": "HashML-DSA-87",
    "2.16.840.1.101.3.4.3.35": "HashSLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.36": "HashSLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.37": "HashSLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.38": "HashSLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.39": "HashSLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.40": "HashSLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.41": "HashSLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.42": "HashSLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.43": "HashSLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.44": "HashSLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.45": "HashSLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.46": "HashSLH-DSA-SHAKE-256f",
    # ML-KEM (FIPS 203)
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    # Falcon / FN-DSA (FIPS 206 draft) — OQS-assigned OIDs seen in interop certs
    # (draft-ietf-lamps-pq-composite-sigs may reassign under the NIST arc).
    "1.3.9999.3.6": "Falcon-512",
    "1.3.9999.3.9": "Falcon-1024",
    # Hash algorithms (bare)
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
    "1.2.840.113549.2.5": "MD5",
}

_FRIENDLY_MAP: dict[str, str] = {
    "sha256withrsaencryption": "RSA-SHA256",
    "sha384withrsaencryption": "RSA-SHA384",
    "sha512withrsaencryption": "RSA-SHA512",
    "sha224withrsaencryption": "RSA-SHA224",
    "sha1withrsaencryption": "RSA-SHA1",
    "md5withrsaencryption": "RSA-MD5",
    "rsassa-pss": "RSA-PSS",
    "rsassapss": "RSA-PSS",
    "ecdsa-with-sha1": "ECDSA-SHA1",
    "ecdsa-with-sha224": "ECDSA-SHA224",
    "ecdsa-with-sha256": "ECDSA-SHA256",
    "ecdsa-with-sha384": "ECDSA-SHA384",
    "ecdsa-with-sha512": "ECDSA-SHA512",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "dsa-with-sha1": "DSA-SHA1",
    "dsa-with-sha256": "DSA-SHA256",
    "id-ml-kem-512": "ML-KEM-512",
    "id-ml-kem-768": "ML-KEM-768",
    "id-ml-kem-1024": "ML-KEM-1024",
    "id-ml-dsa-44": "ML-DSA-44",
    "id-ml-dsa-65": "ML-DSA-65",
    "id-ml-dsa-87": "ML-DSA-87",
    # Pre-standard names still emitted by OpenSSL/liboqs builds.
    "kyber512": "ML-KEM-512",
    "kyber768": "ML-KEM-768",
    "kyber1024": "ML-KEM-1024",
    "dilithium2": "ML-DSA-44",
    "dilithium3": "ML-DSA-65",
    "dilithium5": "ML-DSA-87",
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
_DH_RE = re.compile(r"^(?:DH|DHE|FFDHE)-?(\d+)$", re.IGNORECASE)
_DSA_RE = re.compile(r"^DSA-?(\d+)$", re.IGNORECASE)
_EC_BITS_RE = re.compile(r"(?:P-?|SECP|PRIME)(\d{3})", re.IGNORECASE)

# Quantum-ready primitive prefixes. Composite / hybrid names (a classical
# curve concatenated with ML-KEM/ML-DSA) also count as ready — the hybrid
# resists a quantum adversary as long as the PQC half holds.
_PQC_READY_PREFIXES: tuple[str, ...] = (
    "ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "FALCON", "SPHINCS",
    "DILITHIUM", "KYBER", "FRODOKEM", "NTRU", "CLASSIC-MCELIECE",
    "BIKE", "HQC", "XMSS", "LMS",
    # Pre-hash FIPS 204/205 variants (HashML-DSA / HashSLH-DSA) — the "Hash"
    # prefix means a bare "ML-DSA"/"SLH-DSA" startswith won't match.
    "HASHML-DSA", "HASHSLH-DSA",
    # NIST additional-signature "on-ramp" candidates (Round 2, 2024) and other
    # post-quantum schemes shipped by liboqs / oqs-provider. Not yet FIPS-final
    # (like FN-DSA/Falcon above), but quantum-resistant by design, so a system
    # advertising them is PQC-ready — recognizing them keeps such findings out
    # of the INFO/"unknown" bucket. Names per oqs-provider ALGORITHMS.md.
    # CROSS uses its variant prefix (not bare "CROSS") to avoid matching the
    # X.509 "cross-signed" cert relationship; UOV covers the family name.
    "MAYO", "SNOVA", "CROSSRSDP", "CROSS-RSDP", "HAWK", "SQISIGN", "UOV",
)
_PQC_HYBRID_FRAGMENTS: tuple[str, ...] = ("MLKEM", "MLDSA", "ML-KEM", "ML-DSA")

# Broken / cryptographically dead — a classical computer already defeats
# these, so they are the worst tier regardless of quantum threat.
_BROKEN: frozenset[str] = frozenset({
    "MD5", "MD4", "MD2", "RSA-MD5",
    "SHA-1", "SHA1", "RSA-SHA1", "ECDSA-SHA1", "DSA-SHA1",
    "RC4", "RC2", "DES", "3DES", "TRIPLEDES", "TDES",
})


def _pqc_ready(a: str) -> bool:
    if any(a.startswith(p) for p in _PQC_READY_PREFIXES):
        return True
    # Hybrid: a classical token glued to a PQC token (X25519MLKEM768,
    # P256+ML-KEM-768, secp256r1_mlkem768, ...).
    return any(frag in a for frag in _PQC_HYBRID_FRAGMENTS)


def classify(alg: str) -> Classification:
    """Map a normalised algorithm to a PQC threat classification.

    Tiers (spec Appendix B): SANGAT_TINGGI (broken now / quantum-broken +
    weak) > TINGGI (quantum-broken) > SEDERHANA (quantum-weakened) >
    RENDAH (quantum-safe headroom) > PQC_READY > INFO (unknown/opaque).
    """
    a = normalise(alg).upper()

    if _pqc_ready(a):
        return Classification.PQC_READY

    if a in _BROKEN or a == "DSA":
        return Classification.SANGAT_TINGGI

    # RSA / RSASSA-PSS by modulus size.
    if m := _RSA_RE.match(a):
        return (
            Classification.SANGAT_TINGGI
            if int(m.group(1)) < 3072
            else Classification.TINGGI
        )
    # RSA signature-alg names without an explicit modulus (RSA-SHA256,
    # RSA-PSS, bare RSA). Quantum-forgeable → TINGGI, not opaque INFO.
    if a.startswith(("RSA-", "RSA")) or a == "RSA":
        return Classification.TINGGI

    if m := _DH_RE.match(a):
        return (
            Classification.SANGAT_TINGGI
            if int(m.group(1)) < 3072
            else Classification.TINGGI
        )
    if m := _DSA_RE.match(a):
        return Classification.SANGAT_TINGGI  # DSA is dead regardless of size

    # ECDSA / EdDSA / ECDH — quantum-broken (Shor) → TINGGI.
    if (
        a.startswith(("ECDSA", "ECDH", "ED25519", "ED448", "SM2"))
        or a in {"ECDSA", "EDDSA"}
        or _EC_BITS_RE.search(a)
    ):
        return Classification.TINGGI

    # TLS 1.3 AEAD cipher-suite names carry no key-exchange (that is separate
    # in 1.3), so classify them by the symmetric strength they name rather than
    # letting them fall through to INFO.
    if a.startswith("TLS_"):
        if "AES_256" in a or "CHACHA20" in a:
            return Classification.RENDAH
        if "AES_128" in a:
            return Classification.SEDERHANA

    # Symmetric — Grover halves the effective key length.
    if a.startswith("AES-128") or a == "AES-128":
        # GCM/CCM AEAD at 128-bit still has a 64-bit quantum floor → weakened.
        return Classification.SEDERHANA if "GCM" in a or "CCM" in a else Classification.TINGGI
    if a.startswith(("AES-192", "AES-256", "CHACHA20")) or a in {"AES-192", "AES-256"}:
        return Classification.RENDAH

    # Hashes — collision/preimage margin under Grover.
    if a in {"SHA-224", "SHA224"}:
        return Classification.SEDERHANA
    if a in {"SHA-256", "SHA256", "SHA3-256"}:
        return Classification.SEDERHANA
    if a in {"SHA-384", "SHA384", "SHA-512", "SHA512", "SHA3-384", "SHA3-512"}:
        return Classification.RENDAH

    return Classification.INFO


# --- harvest-now-decrypt-later + migration-deadline logic ----------------
# Key-establishment primitives are the HNDL-critical class: traffic captured
# today is decryptable once a CRQC exists, so their migration deadline is the
# earliest. Signatures are forgeable-in-future (not retroactively), so they
# ride the later CNSA-2.0 milestone. Symmetric/hash need size bumps, not
# replacement.
_KEY_ESTABLISHMENT_RE = re.compile(
    r"^(RSA|DH|DHE|FFDHE|ECDH|ECDHE|X25519|X448)", re.IGNORECASE
)


def is_key_establishment(alg: str) -> bool:
    a = normalise(alg).upper()
    if _pqc_ready(a):
        return False
    return bool(_KEY_ESTABLISHMENT_RE.match(a))


def hndl_exposed(alg: str) -> bool:
    """True when traffic protected by `alg` is harvest-now-decrypt-later
    exposed: a classical key-establishment primitive with no PQC hybrid."""
    return is_key_establishment(alg)


# CNSA 2.0 migration calendar (NSA, 2022) — the deadlines pqcscan scores
# against. HNDL-exposed key establishment is the urgent class.
CNSA2_HNDL_DEADLINE = "2030-01-01"   # begin exclusive PQC for key establishment
CNSA2_FULL_DEADLINE = "2035-01-01"   # full transition, all classes


def migration_deadline(alg: str, classification: Classification | None = None) -> str | None:
    """Return the ISO date by which `alg` should be migrated, or None when
    it is already quantum-safe / not applicable."""
    cls = classification or classify(alg)
    if cls in (Classification.PQC_READY, Classification.RENDAH, Classification.INFO,
               Classification.ERROR):
        return None
    if hndl_exposed(alg):
        return CNSA2_HNDL_DEADLINE
    return CNSA2_FULL_DEADLINE
