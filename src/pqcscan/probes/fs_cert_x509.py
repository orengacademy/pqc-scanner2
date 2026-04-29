from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_EXTS = (".pem", ".crt", ".cer", ".der")


class FsCertX509(Probe):
    id = "fs.cert.x509"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc"), Path("/usr/local/etc")]

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
        try:
            cert = x509.load_pem_x509_certificate(data)
        except ValueError:
            try:
                cert = x509.load_der_x509_certificate(data)
            except ValueError:
                return
        pk = cert.public_key()
        alg = _key_algorithm(pk)
        cls = classify(alg)
        emit(Finding(
            probe_id=self.id,
            algorithm=alg,
            classification=cls,
            severity=_sev(cls),
            title=f"{path.name}: {alg}",
            evidence={
                "path": str(path),
                "subject": cert.subject.rfc4514_string(),
                "not_after": cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after.isoformat(),
            },
        ))


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
