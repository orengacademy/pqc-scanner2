"""net.starttls.ldap — LDAP ExtendedRequest 1.3.6.1.4.1.1466.20037 + TLS upgrade."""
from __future__ import annotations

import asyncio
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


# LDAPv3 ExtendedRequest with OID 1.3.6.1.4.1.1466.20037 (StartTLS).
# Hand-built DER:
#   30 1d                          # SEQUENCE { LDAPMessage
#     02 01 01                     # messageID = 1
#     77 18                        # ExtendedRequest [APPLICATION 23]
#       80 16                      # requestName [0] OCTET STRING
#         312e332e362e312e342e312e313436362e3230303337  # "1.3.6.1.4.1.1466.20037"
_STARTTLS_REQ = bytes.fromhex(
    "301d020101"
    "7718"
    "8016"
    "312e332e362e312e342e312e313436362e3230303337"
)


class NetStarttlsLdap(Probe):
    id = "net.starttls.ldap"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 389, verify: bool = False,
                 timeout_s: float = 10.0):
        self.host, self.port = host, port
        self.verify = verify
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout_s,
            )
        except (OSError, asyncio.TimeoutError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"LDAP STARTTLS connection failed at {self.host}:{self.port}: {e}",
            ))
            return
        try:
            writer.write(_STARTTLS_REQ); await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout_s)
            except asyncio.TimeoutError:
                return
            # ExtendedResponse begins with 0x30 (SEQUENCE) tag; success = result code 0.
            # Parse minimally: look for BER-encoded INTEGER 0 (resultCode success).
            if len(resp) < 12 or 0x0a not in resp[:32]:
                emit(Finding(
                    probe_id=self.id, algorithm="N/A",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"LDAP at {self.host}:{self.port} did not accept STARTTLS",
                    evidence={"endpoint": f"{self.host}:{self.port}",
                              "response_bytes": len(resp)},
                ))
                return
            # Upgrade to TLS.
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
                    timeout=self.timeout_s,
                )
            except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
                emit(Finding(
                    probe_id=self.id, algorithm="N/A",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"LDAP STARTTLS handshake failed at {self.host}:{self.port}: {e}",
                ))
                return
            ssl_obj = ssl_transport.get_extra_info("ssl_object")
            cert_bin = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            cipher = ssl_transport.get_extra_info("cipher")
            ssl_transport.close()
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
                probe_id=self.id, algorithm=normalise(cname),
                classification=cls, severity=sev_for(cls),
                title=f"LDAP STARTTLS {tlsver} cipher {cname}",
                evidence={"endpoint": f"{self.host}:{self.port}", "version": tlsver},
            ))
        if cert_bin:
            cert = x509.load_der_x509_certificate(cert_bin)
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
                probe_id=self.id, algorithm=alg,
                classification=cls, severity=sev_for(cls),
                title=f"LDAP STARTTLS cert {alg}",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "subject": cert.subject.rfc4514_string()},
            ))
