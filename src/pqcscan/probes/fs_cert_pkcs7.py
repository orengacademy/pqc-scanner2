from __future__ import annotations

import warnings
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.utils import CryptographyDeprecationWarning

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".p7b", ".p7c", ".p7s")


class FsCertPkcs7(Probe):
    """Parse PKCS#7 / CMS certificate bundles and classify each contained cert."""
    id = "fs.cert.pkcs7"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/ssl"), Path("/etc/pki")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in _EXTS:
                    self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        certs = self._load(data)
        for cert in certs:
            try:
                self._emit_cert(path, cert, emit)
            except (ValueError, TypeError):
                continue

    def _load(self, data: bytes) -> list[x509.Certificate]:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            try:
                return pkcs7.load_pem_pkcs7_certificates(data)
            except ValueError:
                try:
                    return pkcs7.load_der_pkcs7_certificates(data)
                except (ValueError, TypeError):
                    return []

    def _emit_cert(self, path: Path, cert: x509.Certificate, emit: Emitter) -> None:
        pk = cert.public_key()
        key_alg = _key_algorithm(pk)
        sig_alg = _signature_algorithm(cert)
        key_cls = classify(key_alg)
        sig_cls = classify(sig_alg) if sig_alg else Classification.INFO
        # A weak signature hash (SHA-1/MD5) outranks the key strength.
        cls = _worst(key_cls, sig_cls)
        subject = _short_subject(cert)
        emit(Finding(
            probe_id=self.id,
            algorithm=normalise(key_alg),
            classification=cls,
            severity=_sev(cls),
            title=f"{path.name}: {subject} ({key_alg})",
            evidence={
                "path": str(path),
                "subject": subject,
                "key_algorithm": key_alg,
                "signature_algorithm": sig_alg,
            },
        ))


def _worst(a: Classification, b: Classification) -> Classification:
    """Return the higher-risk of two classifications."""
    order = {
        Classification.PQC_READY: 0,
        Classification.INFO: 1,
        Classification.ERROR: 1,
        Classification.RENDAH: 2,
        Classification.SEDERHANA: 3,
        Classification.TINGGI: 4,
        Classification.SANGAT_TINGGI: 5,
    }
    return a if order[a] >= order[b] else b


def _short_subject(cert: x509.Certificate) -> str:
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn:
            return str(cn[0].value)
    except (ValueError, IndexError):
        pass
    return cert.subject.rfc4514_string()


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


def _signature_algorithm(cert: x509.Certificate) -> str | None:
    try:
        h = cert.signature_hash_algorithm
    except Exception:  # unsupported sig algs raise broad errors
        return None
    if h is None:
        return None
    name = h.name.upper().replace("SHA", "SHA-") if h.name.startswith("sha") else h.name.upper()
    return name


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
