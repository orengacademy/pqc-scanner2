from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".csr", ".req")


class FsCertCsr(Probe):
    id = "fs.cert.csr"
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
        try:
            csr = x509.load_pem_x509_csr(data)
        except ValueError:
            try:
                csr = x509.load_der_x509_csr(data)
            except ValueError:
                return
        pk = csr.public_key()
        alg = _key_algorithm(pk)
        sig_hash = _signature_hash(csr)

        # Worst of {public-key algorithm, signature hash} drives the finding.
        # classify() keys DSA off the bare name, so feed it that while keeping
        # the sized label ("DSA-1024") for the human-facing evidence/title.
        key_cls = classify("DSA" if alg.startswith("DSA-") else alg)
        candidates: list[tuple[str, Classification]] = [(alg, key_cls)]
        if sig_hash is not None:
            candidates.append((sig_hash, classify(sig_hash)))
        worst_alg, worst_cls = max(
            candidates, key=lambda c: _sev(c[1]).numeric
        )

        emit(Finding(
            probe_id=self.id,
            algorithm=worst_alg,
            classification=worst_cls,
            severity=_sev(worst_cls),
            title=f"{path.name}: {alg} signed with {sig_hash or 'unknown'}",
            evidence={
                "path": str(path),
                "subject": csr.subject.rfc4514_string(),
                "public_key": alg,
                "signature_hash": sig_hash,
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


def _signature_hash(csr: x509.CertificateSigningRequest) -> str | None:
    h = csr.signature_hash_algorithm
    if h is None:
        # Ed25519 / Ed448 carry no separate hash algorithm.
        return None
    return h.name.upper()


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
