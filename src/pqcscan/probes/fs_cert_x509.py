from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from pqcscan.core.alg import classify
from pqcscan.core.keyhealth import analyze_rsa_modulus
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._keyalg import key_algorithm as _key_algorithm
from pqcscan.probes._severity import sev_for

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
        # Suppress CryptographyDeprecationWarning for negative-serial certs
        # (Microsoft Code Verification Root et al.). cryptography >= 45 will
        # refuse them; for now keep the inventory by silencing the warning.
        import warnings

        from cryptography.utils import CryptographyDeprecationWarning
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                cert = x509.load_pem_x509_certificate(data)
        except ValueError:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", CryptographyDeprecationWarning)
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
            severity=sev_for(cls),
            title=f"{path.name}: {alg}",
            evidence={
                "path": str(path),
                "subject": cert.subject.rfc4514_string(),
                "not_after": cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after.isoformat(),
            },
        ))
        # Classical key-health checks on public material only: a ROCA
        # (CVE-2017-15361) or sub-1024-bit modulus is exploitable today,
        # independent of the quantum timeline.
        if isinstance(pk, rsa.RSAPublicKey):
            health = analyze_rsa_modulus(pk.public_numbers().n, pk.key_size)
            for issue in health.issues:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=alg,
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=f"{path.name}: classically weak RSA public key",
                    evidence={
                        "path": str(path),
                        "keyhealth": issue,
                        "verified": True,
                    },
                ))




