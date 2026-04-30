from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_EXTS = (".key", ".pem", ".priv")


class FsCertPrivkey(Probe):
    id = "fs.cert.privkey"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:key", "bukukerja:key", "mykripto:key")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/ssl/private"), Path("/etc/pki/tls/private")]

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
            key = load_pem_private_key(data, password=None)
        except (ValueError, TypeError):
            return  # encrypted or unsupported format; skip silently
        alg = _key_algorithm(key)
        cls = classify(alg)
        emit(Finding(
            probe_id=self.id,
            algorithm=alg,
            classification=cls,
            severity=_sev(cls),
            title=f"private key {path.name} uses {alg}",
            evidence={"path": str(path)},
        ))


def _key_algorithm(key: object) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ECDSA-{key.curve.name}"
    if isinstance(key, dsa.DSAPrivateKey):
        return f"DSA-{key.key_size}"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    return type(key).__name__


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
