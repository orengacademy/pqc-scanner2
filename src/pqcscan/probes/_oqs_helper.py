"""Open Quantum Safe (liboqs-python) graceful-import wrapper.

Plan I.7.a foundation. Future probes (net.tls.pqc_handshake, fs.cert.pqc_x509,
host.openssl.oqs_provider, KAT runners) gate on `oqs_available()`. Without
the `pqcscan[active]` extras installed, all OQS-dependent probes self-skip
with INFO finding.

Install: `pip install pqcscan[active]` (requires native liboqs >= 0.10 on host).
"""
from __future__ import annotations

from typing import Any

_oqs: Any = None
_OQS_IMPORT_ERROR: BaseException | None = None
try:
    import oqs as _oqs  # type: ignore[import-not-found,no-redef]
except (ImportError, OSError) as e:
    _OQS_IMPORT_ERROR = e


def oqs_available() -> bool:
    """True iff liboqs-python imported successfully (extras installed + native lib found)."""
    return _oqs is not None


def oqs_import_error() -> str | None:
    """Return repr of the import error, or None if OQS is available."""
    return repr(_OQS_IMPORT_ERROR) if _OQS_IMPORT_ERROR else None


def supported_kems() -> list[str]:
    """List liboqs-supported KEM mechanisms (e.g. 'ML-KEM-768', 'Kyber512')."""
    if _oqs is None:
        return []
    return list(_oqs.get_enabled_kem_mechanisms())


def supported_sigs() -> list[str]:
    """List liboqs-supported signature mechanisms (e.g. 'ML-DSA-65', 'Falcon-512')."""
    if _oqs is None:
        return []
    return list(_oqs.get_enabled_sig_mechanisms())


def kem(name: str) -> Any:
    """Construct a KEM context for `name`. Caller must check oqs_available() first."""
    if _oqs is None:
        raise RuntimeError(f"liboqs not available: {_OQS_IMPORT_ERROR}")
    return _oqs.KeyEncapsulation(name)


def signature(name: str) -> Any:
    """Construct a Signature context for `name`. Caller must check oqs_available() first."""
    if _oqs is None:
        raise RuntimeError(f"liboqs not available: {_OQS_IMPORT_ERROR}")
    return _oqs.Signature(name)
