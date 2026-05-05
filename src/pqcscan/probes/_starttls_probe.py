"""Plaintext greeting + STARTTLS upgrade helper (SMTP / IMAP / POP3 / FTP)."""
from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, Severity


@dataclass(frozen=True, slots=True)
class StartTlsProtocol:
    """Per-protocol STARTTLS plumbing."""
    name: str
    # Lines (terminated CRLF) to send before STARTTLS, in order. Use {host}
    # for the local hostname (e.g. SMTP EHLO).
    pre_lines: tuple[str, ...]
    starttls_line: str
    # Substring expected in the success response (case-insensitive).
    success_marker: str
    greeting_lines: int = 1


SMTP = StartTlsProtocol(
    name="smtp",
    pre_lines=("EHLO {host}",),
    starttls_line="STARTTLS",
    success_marker="220",
    greeting_lines=1,
)
IMAP = StartTlsProtocol(
    name="imap",
    pre_lines=(),
    starttls_line="a001 STARTTLS",
    success_marker="a001 ok",
    greeting_lines=1,
)
POP3 = StartTlsProtocol(
    name="pop3",
    pre_lines=(),
    starttls_line="STLS",
    success_marker="+ok",
    greeting_lines=1,
)
FTP = StartTlsProtocol(
    name="ftp",
    pre_lines=(),
    starttls_line="AUTH TLS",
    success_marker="234",
    greeting_lines=1,
)


async def run_starttls_probe(
    *,
    host: str,
    port: int,
    protocol: StartTlsProtocol,
    probe_id: str,
    emit: Callable[[Finding], None],
    verify: bool = False,
    connect_timeout_s: float = 10.0,
) -> None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=connect_timeout_s,
        )
    except (TimeoutError, OSError) as e:
        emit(Finding(
            probe_id=probe_id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"STARTTLS({protocol.name}) connection failed at {host}:{port}: {e}",
        ))
        return

    try:
        # Read greeting.
        for _ in range(protocol.greeting_lines):
            try:
                await asyncio.wait_for(reader.readline(), timeout=5.0)
            except TimeoutError:
                break

        # Send pre-STARTTLS lines (e.g. SMTP EHLO).
        for line in protocol.pre_lines:
            writer.write((line.format(host=host) + "\r\n").encode("ascii"))
        if protocol.pre_lines:
            await writer.drain()
            # Drain multi-line response.
            for _ in range(20):
                try:
                    raw = await asyncio.wait_for(reader.readline(), timeout=2.0)
                except TimeoutError:
                    break
                if not raw:
                    break
                # SMTP multi-line replies use "250-" continuation, "250 " end.
                if raw[:4] in (b"250 ", b"220 ", b"234 "):
                    break

        # Send STARTTLS command.
        writer.write((protocol.starttls_line + "\r\n").encode("ascii"))
        await writer.drain()
        try:
            response_raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
        except TimeoutError:
            response_raw = b""
        response = response_raw.decode("ascii", errors="replace").strip().lower()

        if protocol.success_marker not in response:
            emit(Finding(
                probe_id=probe_id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=(
                    f"STARTTLS({protocol.name}) refused by {host}:{port}: "
                    f"{response_raw.decode('ascii', errors='replace').strip()}"
                ),
            ))
            return

        # Upgrade transport to TLS.
        sslctx = ssl.create_default_context()
        if not verify:
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE
        try:
            ssl_transport = await asyncio.wait_for(
                asyncio.get_event_loop().start_tls(
                    writer.transport, writer.transport.get_protocol(),
                    sslctx, server_hostname=host,
                ),
                timeout=connect_timeout_s,
            )
        except (TimeoutError, OSError, ssl.SSLError) as e:
            emit(Finding(
                probe_id=probe_id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"STARTTLS({protocol.name}) TLS handshake failed at {host}:{port}: {e}",
            ))
            return

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
            probe_id=probe_id,
            algorithm=normalise(cname),
            classification=cls,
            severity=_sev(cls),
            title=f"STARTTLS({protocol.name}) {tlsver} negotiated cipher {cname}",
            evidence={"endpoint": f"{host}:{port}", "version": tlsver,
                      "protocol": protocol.name},
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
            probe_id=probe_id,
            algorithm=alg,
            classification=cls,
            severity=_sev(cls),
            title=f"STARTTLS({protocol.name}) server cert uses {alg}",
            evidence={
                "endpoint": f"{host}:{port}",
                "subject": cert.subject.rfc4514_string(),
                "not_after": not_after,
                "protocol": protocol.name,
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
