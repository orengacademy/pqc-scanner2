"""Shared TLS connect-and-parse helper for all net.tls.* probes."""
from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, Severity


async def run_tls_probe(
    *,
    host: str,
    port: int,
    verify: bool,
    probe_id: str,
    emit: Callable[[Finding], None],
    connect_timeout_s: float = 10.0,
) -> None:
    """Open a TLS connection, parse cipher suite + server cert, emit Findings.

    On connect failure emits an INFO finding describing the error;
    callers (e.g., net.tls.* probes) treat this as best-effort.
    """
    sslctx = ssl.create_default_context()
    if not verify:
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=sslctx, server_hostname=host,
            ),
            timeout=connect_timeout_s,
        )
    except (TimeoutError, OSError) as e:
        emit(Finding(
            probe_id=probe_id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"TLS connection failed at {host}:{port}: {e}",
        ))
        return

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        cert_bin = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        cipher = writer.get_extra_info("cipher")  # (name, version, bits)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    if cipher:
        cname, tlsver, _ = cipher
        cls = classify(cname)
        emit(Finding(
            probe_id=probe_id,
            algorithm=normalise(cname),
            classification=cls,
            severity=_sev(cls),
            title=f"{tlsver} negotiated cipher {cname}",
            evidence={"endpoint": f"{host}:{port}", "version": tlsver},
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
            title=f"server cert uses {alg}",
            evidence={
                "endpoint": f"{host}:{port}",
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
