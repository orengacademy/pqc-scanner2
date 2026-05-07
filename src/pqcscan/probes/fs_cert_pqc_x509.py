"""fs.cert.pqc_x509 — detect ML-DSA / SLH-DSA / Falcon X.509 certs (Plan I.7.c).

Walks ctx.scan_paths for X.509 cert files (.pem, .crt, .cer, .der), parses
each via `cryptography.x509`, and emits a Finding when signature_algorithm_oid
matches a NIST FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA) / Falcon-assigned OID.

NIST OID assignments under 2.16.840.1.101.3.4.3:
- .17 — ML-DSA-44
- .18 — ML-DSA-65
- .19 — ML-DSA-87
- .20-.31 — SLH-DSA-* (SHA2/SHAKE x 128/192/256 x small/fast)
"""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_PQC_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    # Falcon (OQS-assigned, draft-ietf-lamps-pq-composite-sigs may reassign).
    "1.3.9999.3.6": "Falcon-512",
    "1.3.9999.3.9": "Falcon-1024",
}

_DEFAULT_GLOBS = ("*.pem", "*.crt", "*.cer", "*.der")


def _load_cert(path: Path) -> x509.Certificate | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return None


class FsCertPqcX509(Probe):
    id = "fs.cert.pqc_x509"
    family = ProbeFamily.FILESYSTEM
    framework_tags = (
        "nist-ir-8547:cert", "cnsa2:cert", "bukukerja:cert",
        "mykripto:cert", "nacsa-9:pqc-readiness",
    )

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in ctx.scan_paths:
            if not root.is_dir():
                continue
            for pat in _DEFAULT_GLOBS:
                for path in root.rglob(pat):
                    cert = _load_cert(path)
                    if cert is None:
                        continue
                    try:
                        sig_oid = cert.signature_algorithm_oid.dotted_string
                    except AttributeError:
                        continue
                    if sig_oid not in _PQC_OIDS:
                        continue
                    alg = _PQC_OIDS[sig_oid]
                    try:
                        subject = cert.subject.rfc4514_string()
                    except Exception:
                        subject = "<unparseable>"
                    pem_head = cert.public_bytes(Encoding.PEM)[:80].decode(
                        "ascii", errors="replace",
                    )
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=alg,
                        classification=Classification.PQC_READY,
                        severity=Severity.INFO,
                        title=f"PQC cert at {path} — {alg}",
                        evidence={
                            "path": str(path),
                            "signature_algorithm_oid": sig_oid,
                            "signature_algorithm": alg,
                            "subject": subject,
                            "pem_head": pem_head,
                        },
                    ))
