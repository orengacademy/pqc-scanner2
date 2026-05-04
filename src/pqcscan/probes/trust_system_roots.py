"""trust.system_roots — sample the system CA bundle for weak signatures.

Iterates /etc/ssl/certs/ca-certificates.crt and emits a Finding per cert
whose key type / signature algorithm is sub-PQC. RSA-2048 roots are the
big PQC migration headache because they're long-lived; flag them explicitly.
"""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


_BUNDLE_PATHS = (
    Path("/etc/ssl/certs/ca-certificates.crt"),  # Debian/Ubuntu
    Path("/etc/pki/tls/certs/ca-bundle.crt"),    # RHEL/CentOS
    Path("/etc/ssl/cert.pem"),                   # macOS / Alpine
)


class TrustSystemRoots(Probe):
    id = "trust.system_roots"
    family = ProbeFamily.DNS_EMAIL  # web auth / TLS trust
    framework_tags = ("nist-ir-8547:trust", "bukukerja:trust", "mykripto:trust")

    def __init__(self, bundle_paths: tuple[Path, ...] | None = None,
                 max_certs: int = 200):
        self.bundle_paths = bundle_paths or _BUNDLE_PATHS
        self.max_certs = max_certs

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.bundle_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for bundle in self.bundle_paths:
            if not bundle.exists():
                continue
            try:
                pem = bundle.read_bytes()
            except OSError:
                continue
            certs = x509.load_pem_x509_certificates(pem)[: self.max_certs]
            for cert in certs:
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
                # Only surface non-PQC-aligned roots; AES-256-only certs
                # don't exist in trust stores, so cls is always Sangat
                # Tinggi / Tinggi unless someone ships a Falcon root.
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    subject = cert.subject.rfc4514_string()
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=alg,
                        classification=cls, severity=sev_for(cls),
                        title=f"trust root: {alg} {subject[:60]}",
                        evidence={"bundle": str(bundle),
                                  "subject": subject,
                                  "not_after": cert.not_valid_after_utc.isoformat()
                                  if hasattr(cert, "not_valid_after_utc")
                                  else cert.not_valid_after.isoformat()},
                    ))
