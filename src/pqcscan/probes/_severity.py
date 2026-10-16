"""Shared classification → severity mapping used by every probe."""
from __future__ import annotations

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Severity


def sev_for(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]


# Substrings of weak primitives embedded in RFC TLS cipher-suite names
# like "TLS_RSA_WITH_RC4_128_SHA" — classify() can't decompose those,
# so we substring-match.
_WEAK_SUBSTR: tuple[tuple[str, Classification], ...] = (
    ("RC4",      Classification.SANGAT_TINGGI),
    ("RC2",      Classification.SANGAT_TINGGI),
    ("3DES",     Classification.SANGAT_TINGGI),
    ("DES_CBC",  Classification.SANGAT_TINGGI),
    ("_DES_",    Classification.SANGAT_TINGGI),
    ("EXPORT",   Classification.SANGAT_TINGGI),
    ("EXP_",     Classification.SANGAT_TINGGI),
    ("NULL",     Classification.SANGAT_TINGGI),
    ("ANON",     Classification.SANGAT_TINGGI),
    ("MD5",      Classification.SANGAT_TINGGI),
)


def classify_cipher_token(token: str) -> Classification:
    """Classify a TLS cipher-suite token.

    First tries classify() on the normalised name (which works for
    short OpenSSL names). For RFC-style composite names like
    "TLS_RSA_WITH_RC4_128_SHA" classify() returns INFO, so we fall
    back to substring matching against known weak primitives.
    """
    direct = classify(normalise(token))
    if direct is not Classification.INFO:
        return direct
    up = token.upper()
    for needle, cls in _WEAK_SUBSTR:
        if needle in up:
            return cls
    return Classification.INFO


def classify_suite(name: str) -> Classification:
    """Classify a TLS cipher suite by its RFC name for PQC exposure.

    Weak symmetric primitives (RC4/3DES/DES/MD5/NULL/EXPORT/anon) and legacy
    CBC-mode-with-SHA1 suites are SANGAT_TINGGI; static-RSA key transport and
    classical (EC)DHE key exchange are quantum-broken -> TINGGI. Bare TLS 1.3
    AEAD suites carry no KEX in the name (that lives in key_share) -> INFO.
    """
    up = name.upper()
    base = classify_cipher_token(name)
    if base is Classification.SANGAT_TINGGI:
        return base
    if up.endswith("_CBC_SHA"):  # CBC cipher + SHA-1 MAC, no AEAD
        return Classification.SANGAT_TINGGI
    if "_RSA_WITH" in up and "DHE" not in up:  # static-RSA key transport
        return Classification.TINGGI
    if "ECDHE" in up or "ECDH_" in up or "DHE_" in up:  # classical KEX
        return Classification.TINGGI
    return base
