"""net.db.postgres_tls — PostgreSQL SSLRequest + TLS upgrade probe.

Sends the 8-byte SSLRequest message (length=0x00000008, code=0x04D2162F).
Server replies 'S' (TLS supported, upgrade) or 'N' (plaintext only) or
ErrorResponse (no SSL support).
"""
from __future__ import annotations

import asyncio
import ssl
import struct

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_SSL_REQUEST = struct.pack("!II", 8, 80877103)  # length=8, code=0x04D2162F


class NetDbPostgresTls(Probe):
    id = "net.db.postgres_tls"
    family = ProbeFamily.NETWORK
    framework_tags = ("bukukerja:db", "mykripto:db", "nist-ir-8547:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 5432, verify: bool = False):
        self.host = host
        self.port = port
        self.verify = verify

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=5.0,
            )
        except (TimeoutError, OSError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"PostgreSQL connection failed at {self.host}:{self.port}: {e}",
            ))
            return

        try:
            writer.write(_SSL_REQUEST)
            await writer.drain()
            try:
                response = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            except (TimeoutError, asyncio.IncompleteReadError):
                response = b""

            if response == b"N":
                emit(Finding(
                    probe_id=self.id, algorithm="PLAINTEXT",
                    classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT,
                    title=f"PostgreSQL at {self.host}:{self.port} refuses TLS (plaintext only)",
                    evidence={"endpoint": f"{self.host}:{self.port}", "response": "N"},
                    remediation={"snippet": "# Enable ssl=on in postgresql.conf"},
                ))
                return
            if response != b"S":
                emit(Finding(
                    probe_id=self.id, algorithm="N/A",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"PostgreSQL at {self.host}:{self.port} returned unexpected SSLRequest reply",
                    evidence={"response": response.hex()},
                ))
                return

            # Server accepted SSL — upgrade.
            sslctx = ssl.create_default_context()
            if not self.verify:
                sslctx.check_hostname = False
                sslctx.verify_mode = ssl.CERT_NONE
            try:
                ssl_transport = await asyncio.wait_for(
                    asyncio.get_event_loop().start_tls(
                        writer.transport, writer.transport.get_protocol(),
                        sslctx, server_hostname=self.host,
                    ),
                    timeout=10.0,
                )
            except (TimeoutError, OSError, ssl.SSLError) as e:
                emit(Finding(
                    probe_id=self.id, algorithm="N/A",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"PostgreSQL TLS handshake failed at {self.host}:{self.port}: {e}",
                ))
                return

            # asyncio.start_tls returns Transport | None; None implies a
            # connection-level failure that would have raised above.
            assert ssl_transport is not None
            ssl_obj = ssl_transport.get_extra_info("ssl_object")
            cert_bin = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            cipher = ssl_transport.get_extra_info("cipher")
            ssl_transport.close()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        if cipher:
            cname, tlsver, _ = cipher
            cls = classify(cname)
            emit(Finding(
                probe_id=self.id, algorithm=normalise(cname),
                classification=cls, severity=_sev(cls),
                title=f"PostgreSQL {tlsver} negotiated cipher {cname}",
                evidence={"endpoint": f"{self.host}:{self.port}", "version": tlsver},
            ))

        if cert_bin:
            cert = x509.load_der_x509_certificate(cert_bin)
            pk = cert.public_key()
            alg = _key_alg(pk)
            cls = classify(alg)
            not_after = (
                cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after.isoformat()
            )
            emit(Finding(
                probe_id=self.id, algorithm=alg,
                classification=cls, severity=_sev(cls),
                title=f"PostgreSQL server cert uses {alg}",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "subject": cert.subject.rfc4514_string(),
                          "not_after": not_after},
            ))


def _key_alg(pk: object) -> str:
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
