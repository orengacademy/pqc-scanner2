"""fs.cert.pqc_x509 — detect ML-DSA / SLH-DSA / Falcon / composite X.509 certs.

Walks ctx.scan_paths for X.509 cert files (.pem, .crt, .cer, .der), parses each
via `cryptography.x509`, and emits a Finding when the cert's signature algorithm
is post-quantum. Recognition is centralized in `core.alg` (a single OID table),
so every standardized PQC signature OID is covered: pure ML-DSA / SLH-DSA (FIPS
204/205), the pre-hash HashML-DSA / HashSLH-DSA variants (CSOR .32-.46), the
LAMPS composite ML-DSA hybrids, and Falcon — not just the pure .17-.31 arc.
"""
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

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
                    # Centralized recognition: PQC iff core.alg classifies the
                    # signature OID as quantum-ready (covers pure + pre-hash +
                    # composite + Falcon).
                    if classify(sig_oid) is not Classification.PQC_READY:
                        continue
                    alg = normalise(sig_oid)
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
