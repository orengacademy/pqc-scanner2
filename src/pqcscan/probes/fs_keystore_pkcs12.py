from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".p12", ".pfx")
_PASSWORDS: tuple[bytes | None, ...] = (None, b"", b"changeit", b"password")


class FsKeystorePkcs12(Probe):
    """Discover and inventory PKCS#12 / PFX keystores under roots."""
    id = "fs.keystore.pkcs12"
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
        key, cert = None, None
        loaded = False
        for pw in _PASSWORDS:
            try:
                key, cert, _ = pkcs12.load_key_and_certificates(data, pw)
                loaded = True
                break
            except (ValueError, TypeError):
                continue
        if not loaded:
            # Could not decrypt with any known password — still inventory it.
            emit(Finding(
                probe_id=self.id,
                algorithm="PKCS12-ENCRYPTED",
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=f"{path.name}: encrypted PKCS#12 keystore (undecryptable)",
                evidence={"path": str(path)},
                remediation={
                    "snippet": "# Inventory PKCS#12 keystore contents; "
                               "verify enclosed key/cert algorithms are quantum-safe.",
                },
            ))
            return
        if key is not None:
            alg, cls = _classify_key(key)
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=cls,
                severity=_sev(cls),
                title=f"{path.name}: private key {alg}",
                evidence={"path": str(path), "kind": "private-key"},
            ))
        if cert is not None:
            sig = _sig_hash(cert)
            scls = _classify_sig_hash(sig)
            emit(Finding(
                probe_id=self.id,
                algorithm=sig,
                classification=scls,
                severity=_sev(scls),
                title=f"{path.name}: leaf certificate signature {sig}",
                evidence={
                    "path": str(path),
                    "kind": "leaf-cert-signature",
                    "subject": cert.subject.rfc4514_string(),
                },
            ))


def _classify_key(key: object) -> tuple[str, Classification]:
    """Return (algorithm-label, classification) for a private key.

    Follows the scanner severity rule directly so EC/Ed25519/DSA are graded
    consistently regardless of which patterns ``classify()`` happens to cover:
      * RSA -> classify() (RSA<3072 sangat-tinggi, else tinggi)
      * DSA -> sangat-tinggi (legacy, broken in practice)
      * EC / Ed25519 / Ed448 -> sederhana (quantum-vulnerable, not broken)
    """
    if isinstance(key, rsa.RSAPrivateKey):
        alg = f"RSA-{key.key_size}"
        return alg, classify(alg)
    if isinstance(key, dsa.DSAPrivateKey):
        return f"DSA-{key.key_size}", Classification.SANGAT_TINGGI
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"EC-{key.curve.name}", Classification.TINGGI
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519", Classification.TINGGI
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448", Classification.TINGGI
    return type(key).__name__, classify(type(key).__name__)


def _sig_hash(cert: object) -> str:
    algo = getattr(cert, "signature_hash_algorithm", None)
    name = getattr(algo, "name", None)
    if not name:
        return "UNKNOWN"
    return str(name).upper()


def _classify_sig_hash(name: str) -> Classification:
    """Classify a certificate signature-hash algorithm per the scanner rule.

    SHA-1 / MD5 signatures are broken in practice -> flag HIGH.
    Modern SHA-2 hashes are not the quantum-weak link (the asymmetric key is)
    so they are informational here.
    """
    n = name.upper().replace("-", "")
    if n in {"SHA1", "MD5", "MD4", "MD2"}:
        return Classification.TINGGI
    return Classification.INFO


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
