"""OS-ssl TLS probes: permissive inventory client + OpenSSL suite-name classification."""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import socket
import ssl
import threading
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pqcscan.core.types import Classification
from pqcscan.probes._severity import classify_suite
from pqcscan.probes._tls_probe import inventory_ssl_context, run_tls_probe


@pytest.mark.parametrize(("suite", "expected"), [
    ("AES256-GCM-SHA384", Classification.TINGGI),           # static-RSA key transport
    ("AES128-SHA", Classification.SANGAT_TINGGI),           # CBC + SHA-1 MAC
    ("DHE-RSA-AES128-GCM-SHA256", Classification.TINGGI),   # finite-field DH
    ("ECDHE-RSA-AES128-GCM-SHA256", Classification.TINGGI),
    ("ECDHE-RSA-AES128-SHA", Classification.SANGAT_TINGGI), # CBC + SHA-1, like TLS_..._CBC_SHA
    ("ADH-AES128-SHA", Classification.SANGAT_TINGGI),       # anonymous
    ("AECDH-NULL-SHA", Classification.SANGAT_TINGGI),       # anonymous, no encryption
    ("EXP-RC4-MD5", Classification.SANGAT_TINGGI),          # export
    ("DES-CBC3-SHA", Classification.SANGAT_TINGGI),         # 3DES
    ("DES-CBC-SHA", Classification.SANGAT_TINGGI),          # single DES
    ("NULL-SHA256", Classification.SANGAT_TINGGI),          # no encryption
    ("PSK-AES128-GCM-SHA256", Classification.SEDERHANA),    # = TLS_PSK_WITH_AES_128_GCM_SHA256
    ("RSA-PSK-AES256-GCM-SHA384", Classification.RENDAH),   # = TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
    ("PSK-AES128-CBC-SHA", Classification.SANGAT_TINGGI),   # = TLS_PSK_WITH_AES_128_CBC_SHA
    ("DHE-PSK-AES128-GCM-SHA256", Classification.TINGGI),   # = TLS_DHE_PSK_WITH_*
    ("TLS_AES_256_GCM_SHA384", Classification.RENDAH),      # TLS 1.3 names unchanged
])
def test_openssl_suite_names(suite: str, expected: Classification) -> None:
    assert classify_suite(suite) is expected


def test_inventory_context_is_permissive_only_without_verify() -> None:
    loose = inventory_ssl_context(verify=False)
    assert loose.verify_mode is ssl.CERT_NONE
    assert loose.minimum_version is ssl.TLSVersion.TLSv1
    strict = inventory_ssl_context(verify=True)
    assert strict.verify_mode is ssl.CERT_REQUIRED
    assert strict.minimum_version is ssl.TLSVersion.TLSv1_2


@contextlib.contextmanager
def _rsa_kex_server(tmp_path: Path):  # type: ignore[no-untyped-def]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "legacy.test")])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=36500))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("AES256-SHA:@SECLEVEL=0")  # TLS 1.0 + static RSA: refused by the stock client
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        conn, _ = srv.accept()
        with contextlib.suppress(OSError), conn, ctx.wrap_socket(conn, server_side=True) as tls:
            tls.recv(1)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield srv.getsockname()[1]
    finally:
        srv.close()


def test_legacy_server_is_inventoried_not_skipped(tmp_path: Path) -> None:
    found: list = []
    with _rsa_kex_server(tmp_path) as port:
        asyncio.run(run_tls_probe(host="127.0.0.1", port=port, verify=False,
                                  probe_id="net.tls.https", emit=found.append))
    got = {(f.algorithm, f.classification) for f in found}
    assert {f.evidence.get("client") for f in found if f.algorithm == "AES256-SHA"} == {"inventory (all suites offered)"}
    assert ("AES256-SHA", Classification.SANGAT_TINGGI) in got
    assert ("RSA-2048", Classification.SANGAT_TINGGI) in got


@pytest.mark.parametrize(("openssl", "rfc"), [
    ("PSK-AES128-GCM-SHA256", "TLS_PSK_WITH_AES_128_GCM_SHA256"),
    ("RSA-PSK-AES256-GCM-SHA384", "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"),
    ("PSK-AES128-CBC-SHA", "TLS_PSK_WITH_AES_128_CBC_SHA"),
    ("SRP-AES-128-CBC-SHA", "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    ("DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    ("AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"),
])
def test_openssl_and_rfc_spellings_agree(openssl: str, rfc: str) -> None:
    assert classify_suite(openssl) is classify_suite(rfc)
