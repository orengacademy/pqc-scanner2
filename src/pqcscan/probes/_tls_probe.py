"""Shared TLS connect-and-parse helper for all net.tls.* probes."""
from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from collections.abc import Callable

from cryptography import x509

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.probes._keyalg import key_algorithm as _key_algorithm
from pqcscan.probes._severity import classify_suite, sev_for


def inventory_ssl_context(verify: bool) -> ssl.SSLContext:
    """Client context for the OS-ssl TLS probes.

    With verification off (inventory mode) the client accepts every protocol
    and suite the local OpenSSL can still speak — TLS 1.0, static-RSA key
    transport, NULL encryption. The stock context refuses those, so the weakest
    servers, the ones an inventory must see, used to yield only "connection
    failed". With ``verify`` the stock, strict context is kept."""
    sslctx = ssl.create_default_context()
    if not verify:
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():  # TLSVersion.TLSv1 is deprecated; offering it is the point
            warnings.simplefilter("ignore", DeprecationWarning)
            sslctx.minimum_version = ssl.TLSVersion.TLSv1
        sslctx.set_ciphers("ALL:eNULL:@SECLEVEL=0")
    return sslctx


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
    sslctx = inventory_ssl_context(verify)

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
        cls = classify_suite(cname)
        emit(Finding(
            probe_id=probe_id,
            algorithm=normalise(cname),
            classification=cls,
            severity=sev_for(cls),
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
            severity=sev_for(cls),
            title=f"server cert uses {alg}",
            evidence={
                "endpoint": f"{host}:{port}",
                "subject": cert.subject.rfc4514_string(),
                "not_after": not_after,
            },
        ))




