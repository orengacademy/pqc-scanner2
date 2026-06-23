from __future__ import annotations

import warnings
from datetime import UTC, date
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.utils import CryptographyDeprecationWarning

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".pem", ".crt", ".cer")

# CNSA 2.0 migration horizon. Certificates whose validity stretches past these
# dates outlive the window in which their classical keys remain trustworthy.
HNDL_DEADLINE = date(2030, 1, 1)
CRQC_DEADLINE = date(2035, 1, 1)

# Classical (quantum-vulnerable) public-key primitives. PQC keys (ML-DSA /
# ML-KEM / SLH-DSA) never deserialise into one of these types.
_CLASSICAL = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    dsa.DSAPublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
)


class FsCertExpiryHorizon(Probe):
    """Correlate X.509 notAfter dates with PQC migration deadlines."""
    id = "fs.cert.expiry_horizon"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/ssl"), Path("/etc/pki"), Path("/etc/ssl/certs")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not (path.is_file() and path.suffix.lower() in _EXTS):
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        cert = _load_cert(data)
        if cert is None:
            return
        # Skip CA certificates (roots + intermediates): the system trust bundle
        # under /etc/ssl/certs is full of long-lived classical CA certs that are
        # the distro's / a CA's migration scope, not the operator's. Flagging
        # them floods the report. End-entity (leaf) certs are the real scope.
        if _is_ca(cert):
            return
        # Only classical-keyed certs carry quantum harvest risk.
        if not isinstance(cert.public_key(), _CLASSICAL):
            return

        not_after = _not_after_date(cert)
        cls, label = _horizon_classification(not_after)
        if cls is None:
            return
        emit(Finding(
            probe_id=self.id,
            algorithm=_key_algorithm(cert.public_key()),
            classification=cls,
            severity=_sev(cls),
            title=f"{path.name}: classical cert valid until {not_after.isoformat()} ({label})",
            evidence={
                "path": str(path),
                "subject": cert.subject.rfc4514_string(),
                "not_after": not_after.isoformat(),
                "hndl_deadline": HNDL_DEADLINE.isoformat(),
                "crqc_deadline": CRQC_DEADLINE.isoformat(),
            },
            remediation={
                "snippet": "# Plan PQC migration (CNSA 2.0) and shorten this cert's lifetime "
                           "or re-key with ML-DSA before the CRQC horizon.",
            },
        ))


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(bc.value.ca)


def _load_cert(data: bytes) -> x509.Certificate | None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            try:
                return x509.load_der_x509_certificate(data)
            except ValueError:
                return None


def _not_after_date(cert: x509.Certificate) -> date:
    dt = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=UTC)  # pragma: no cover - legacy
    )
    return dt.astimezone(UTC).date()


def _horizon_classification(not_after: date) -> tuple[Classification | None, str]:
    if not_after > CRQC_DEADLINE:
        return (
            Classification.TINGGI,
            "will still be live when a cryptographically-relevant quantum computer "
            "is plausible; harvest-now-decrypt-later",
        )
    if not_after > HNDL_DEADLINE:
        return (Classification.SEDERHANA, "outlives the CNSA 2.0 HNDL deadline")
    return (Classification.RENDAH, "expires before the CNSA 2.0 HNDL deadline")


def _key_algorithm(pk: object) -> str:
    if isinstance(pk, rsa.RSAPublicKey):
        return f"RSA-{pk.key_size}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pk.curve.name}"
    if isinstance(pk, dsa.DSAPublicKey):
        return f"DSA-{pk.key_size}"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pk).__name__


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]
