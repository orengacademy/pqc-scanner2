from __future__ import annotations

import asyncio
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class NetTlsHttps(Probe):
    id = "net.tls.https"
    family = ProbeFamily.NETWORK
    framework_tags = (
        "nist-ir-8547:tls", "cnsa2:tls", "bukukerja:tls", "mykripto:tls",
    )

    def __init__(
        self, host: str = "127.0.0.1", port: int = 443, verify: bool = False
    ):
        self.host = host
        self.port = port
        self.verify = verify

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        sslctx = ssl.create_default_context()
        if not self.verify:
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host, self.port,
                    ssl=sslctx, server_hostname=self.host,
                ),
                timeout=10.0,
            )
        except (OSError, asyncio.TimeoutError) as e:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"TLS connection failed at {self.host}:{self.port}: {e}",
            ))
            return

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cert_bin = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            cipher = writer.get_extra_info("cipher")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

        if cipher:
            cname, tlsver, _ = cipher
            cls = classify(cname)
            emit(Finding(
                probe_id=self.id,
                algorithm=normalise(cname),
                classification=cls,
                severity=_sev(cls),
                title=f"{tlsver} negotiated cipher {cname}",
                evidence={
                    "endpoint": f"{self.host}:{self.port}",
                    "version": tlsver,
                },
            ))

        if cert_bin:
            cert = x509.load_der_x509_certificate(cert_bin)
            pk = cert.public_key()
            alg = _key_algorithm(pk)
            cls = classify(alg)
            not_after = (
                cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after.isoformat()
            )
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=cls,
                severity=_sev(cls),
                title=f"server cert uses {alg}",
                evidence={
                    "endpoint": f"{self.host}:{self.port}",
                    "subject": cert.subject.rfc4514_string(),
                    "not_after": not_after,
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
