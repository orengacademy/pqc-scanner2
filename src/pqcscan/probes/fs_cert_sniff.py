"""fs.cert.sniff — X.509 / private-key material in non-standard files.

The other filesystem probes only look at files with a recognised cert/key
suffix (.pem/.crt/.key/.p12/...). Credentials get stored with the wrong
extension (or none) all the time — a leaf cert dumped into `config.txt`, a
private key inlined into a `.conf`, a DER blob under `/srv/data`. This probe
walks files whose suffix is NOT one of the standard ones, applies a cheap
content gate (PEM marker or DER SEQUENCE magic), then tries to parse the gated
hits as a certificate or a private key. Misplaced key material is the finding.
"""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# Suffixes already covered by the dedicated cert/key/keystore probes — skip them
# here so this probe only catches the wrong-extension / extensionless leftovers.
_SKIP_EXTS = frozenset({
    ".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx",
    ".csr", ".req", ".p7b", ".p7c", ".jks", ".jceks",
})

# Files larger than this are not credential blobs — skip to bound the walk.
_MAX_SIZE = 262144

_PEM_CERT_MARKER = b"-----BEGIN CERTIFICATE-----"
# Matches PKCS#8 ("PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY"), SEC1
# ("EC PRIVATE KEY") and encrypted PEM private keys.
_PEM_KEY_MARKER = b"PRIVATE KEY-----"
_DER_MAGIC = b"\x30\x82"


class FsCertSniff(Probe):
    """Sniff cert / private-key material out of non-standard file extensions."""

    id = "fs.cert.sniff"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc"), Path("/opt"), Path("/srv")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                try:
                    if not path.is_file():
                        continue
                    if path.suffix.lower() in _SKIP_EXTS:
                        continue
                    resolved = path.resolve()
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                except OSError:
                    continue
                self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            if path.stat().st_size > _MAX_SIZE:
                return
            data = path.read_bytes()
        except (OSError, ValueError):
            return
        if not _gated(data):
            return
        if self._try_cert(path, data, emit):
            return
        self._try_private_key(path, data, emit)

    def _try_cert(self, path: Path, data: bytes, emit: Emitter) -> bool:
        cert = _load_cert(data)
        if cert is None:
            return False
        # Skip CA certs (roots / intermediates): they are a CA's migration scope,
        # not a misplaced operator credential, and flood the report.
        if _is_ca(cert):
            return True
        pk = cert.public_key()
        alg = _key_algorithm(pk)
        cls = classify(alg)
        # weak (RSA<3072 / DSA / SHA-1 etc.) -> HIGH; otherwise classical -> MED.
        sev = Severity.HIGH if cls is Classification.SANGAT_TINGGI else Severity.MED
        emit(Finding(
            probe_id=self.id,
            algorithm=alg,
            classification=cls,
            severity=sev,
            title=f"{path.name}: {alg} certificate in non-standard file",
            evidence={
                "path": str(path),
                "subject": cert.subject.rfc4514_string(),
                "kind": "certificate",
                "note": f"X.509 certificate found in a non-standard file (suffix "
                        f"{path.suffix or '<none>'!r}); other cert probes skip this path.",
            },
        ))
        return True

    def _try_private_key(self, path: Path, data: bytes, emit: Emitter) -> bool:
        key = _load_private_key(data)
        if key is None:
            return False
        alg = _key_algorithm(key)
        emit(Finding(
            probe_id=self.id,
            algorithm=alg,
            classification=Classification.SEDERHANA,
            severity=Severity.MED,
            title=f"{path.name}: private key material in non-standard file",
            evidence={
                "path": str(path),
                "kind": "private-key",
                "note": f"Private key material ({alg}) found in a non-standard file "
                        f"(suffix {path.suffix or '<none>'!r}); other key probes skip this path.",
            },
        ))
        return True


def _gated(data: bytes) -> bool:
    if _PEM_CERT_MARKER in data or _PEM_KEY_MARKER in data:
        return True
    return data[:2] == _DER_MAGIC


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(bc.value.ca)


def _load_cert(data: bytes) -> x509.Certificate | None:
    try:
        return x509.load_pem_x509_certificate(data)
    except (ValueError, TypeError):
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except (ValueError, TypeError):
        return None


def _load_private_key(data: bytes) -> object | None:
    try:
        return load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        pass
    try:
        return load_der_private_key(data, password=None)
    except (ValueError, TypeError):
        return None


def _key_algorithm(pk: object) -> str:
    if isinstance(pk, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return f"RSA-{pk.key_size}"
    if isinstance(pk, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return f"ECDSA-{pk.curve.name}"
    if isinstance(pk, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return f"DSA-{pk.key_size}"
    if isinstance(pk, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519"
    if isinstance(pk, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
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
