"""Tests for net.tls.cert_chain (TLS 1.2 served-chain reader)."""
import datetime
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_tls_cert_chain import (
    NetTlsCertChain,
    build_client_hello_tls12,
    extract_certificates,
    reassemble_handshake,
)


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _der_cert(key=None, *, hash_alg=None) -> bytes:
    priv = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
    )
    sign_hash = None if hash_alg == "none" else (hash_alg or hashes.SHA256())
    cert = builder.sign(priv, sign_hash)
    return cert.public_bytes(Encoding.DER)


def _cert_message(ders: list[bytes]) -> bytes:
    inner = b"".join(_u24(len(c)) + c for c in ders)
    body = _u24(len(inner)) + inner
    return b"\x0b" + _u24(len(body)) + body          # handshake msg: Certificate


def _record(payload: bytes) -> bytes:
    return b"\x16\x03\x03" + _u16(len(payload)) + payload


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(), server_target=target)


def test_extract_single_cert():
    der = _der_cert()
    certs = extract_certificates(_record(_cert_message([der])))
    assert certs == [der]


def test_extract_full_chain():
    leaf, inter = _der_cert(), _der_cert()
    certs = extract_certificates(_record(_cert_message([leaf, inter])))
    assert certs == [leaf, inter]


def test_reassembly_across_records():
    # A Certificate message split across two TLS records must be rejoined.
    msg = _cert_message([_der_cert()])
    split = len(msg) // 2
    data = _record(msg[:split]) + _record(msg[split:])
    assert len(reassemble_handshake(data)) == len(msg)
    assert len(extract_certificates(data)) == 1


def test_extract_none_when_no_certificate_msg():
    # A ServerHello-only handshake (type 0x02) carries no certs.
    sh = b"\x02" + _u24(4) + b"\x03\x03\x00\x00"
    assert extract_certificates(_record(sh)) == []
    assert extract_certificates(b"") == []


def test_build_client_hello_tls12_structure():
    ch = build_client_hello_tls12("example.com")
    assert ch[:3] == b"\x16\x03\x01"      # handshake record
    assert ch[5] == 0x01                  # ClientHello
    assert ch[9:11] == b"\x03\x03"        # legacy_version TLS 1.2 (after record+hs headers)
    assert b"\x00\x2b" not in ch          # NO supported_versions ext (forces <= TLS 1.2)
    assert b"example.com" in ch


@pytest.mark.asyncio
async def test_run_emits_per_cert(monkeypatch):
    probe = NetTlsCertChain(target="srv:443")
    response = _record(_cert_message([_der_cert(), _der_cert(ec.generate_private_key(ec.SECP256R1()))]))

    async def fake(host, port):
        return response
    monkeypatch.setattr(probe, "_fetch", fake)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert len(found) == 2
    assert found[0].evidence["depth"] == 0 and found[0].evidence["role"] == "leaf"
    assert found[0].algorithm.startswith("RSA")
    assert found[0].classification in (Classification.SANGAT_TINGGI, Classification.TINGGI)
    assert found[0].severity in (Severity.CRIT, Severity.HIGH)


@pytest.mark.asyncio
async def test_run_no_response_no_findings(monkeypatch):
    probe = NetTlsCertChain(target="srv:443")

    async def fake(host, port):
        return b""
    monkeypatch.setattr(probe, "_fetch", fake)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert found == []


@pytest.mark.asyncio
async def test_applies_and_malformed_target():
    assert await NetTlsCertChain(target="x:443").applies(_ctx()) is True
    assert await NetTlsCertChain().applies(_ctx()) is False
    p = NetTlsCertChain()
    assert p._resolve_target(_ctx("host:notaport")) is None
