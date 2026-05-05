"""email.smime.certs — S/MIME (.p7s, .pem in mail dirs) cert key-type scan."""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqcscan.core.alg import classify
from pqcscan.core.types import Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_EXTS = (".p7s", ".p7m", ".smime")


class EmailSmimeCerts(Probe):
    id = "email.smime.certs"
    family = ProbeFamily.DNS_EMAIL
    framework_tags = ("bukukerja:email", "mykripto:email")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/postfix"), Path("/etc/dovecot"),
            Path("/var/mail"), Path("/srv/mail"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in _EXTS:
                    continue
                try:
                    data = path.read_bytes()
                    cert = x509.load_pem_x509_certificate(data)
                except Exception:
                    continue
                pk = cert.public_key()
                if isinstance(pk, rsa.RSAPublicKey):
                    alg = f"RSA-{pk.key_size}"
                elif isinstance(pk, ec.EllipticCurvePublicKey):
                    alg = f"ECDSA-{pk.curve.name}"
                elif isinstance(pk, ed25519.Ed25519PublicKey):
                    alg = "Ed25519"
                elif isinstance(pk, ed448.Ed448PublicKey):
                    alg = "Ed448"
                elif isinstance(pk, dsa.DSAPublicKey):
                    alg = f"DSA-{pk.key_size}"
                else:
                    alg = type(pk).__name__
                cls = classify(alg)
                emit(Finding(
                    probe_id=self.id,
                    algorithm=alg,
                    classification=cls, severity=sev_for(cls),
                    title=f"S/MIME cert {path.name} = {alg}",
                    evidence={"path": str(path), "subject": cert.subject.rfc4514_string()},
                ))
