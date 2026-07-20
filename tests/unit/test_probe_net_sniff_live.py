"""Hermetic tests for net.sniff.live — no real socket is ever opened.

Every case injects a canned ``frame_source`` (raw Ethernet+IPv4+TCP frames we
assemble by hand with ``struct``), so the AF_PACKET path is never touched.
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Capability, Classification, Finding, Severity
from pqcscan.probes._base import ScanContext, SniffConfig
from pqcscan.probes.net_sniff_live import NetSniffLive
from pqcscan.probes.net_tls_cert_chain import build_client_hello_tls12

# --- frame builders ------------------------------------------------------


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _eth_ipv4_tcp(
    payload: bytes,
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "93.184.216.34",
    sport: int = 44300,
    dport: int = 443,
) -> bytes:
    """Wrap a TCP payload in Ethernet II + IPv4 + TCP headers."""
    tcp = (
        _u16(sport) + _u16(dport)
        + struct.pack(">I", 1)         # seq
        + struct.pack(">I", 0)         # ack
        + bytes([0x50, 0x18])          # data offset (20B) | flags PSH+ACK
        + _u16(65535) + _u16(0) + _u16(0)  # window, checksum, urg
        + payload
    )
    ip_body_len = 20 + len(tcp)
    ip = (
        bytes([0x45, 0x00]) + _u16(ip_body_len)
        + _u16(0) + _u16(0)            # id, flags/frag
        + bytes([64, 6]) + _u16(0)     # ttl, proto=TCP, checksum
        + socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    )
    eth = b"\x00" * 6 + b"\x11" * 6 + _u16(0x0800)  # dst, src mac, ethertype IPv4
    return eth + ip + tcp


def _server_hello_record(cipher: int) -> bytes:
    """A minimal TLS ServerHello record negotiating `cipher` (no extensions)."""
    body = (
        b"\x03\x03" + bytes(range(32))  # legacy_version + random
        + b"\x00"                        # session_id length 0
        + _u16(cipher)                   # cipher_suite
        + b"\x00"                        # compression_method
    )
    handshake = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + _u16(len(handshake)) + handshake


def _certificate_record(der: bytes) -> bytes:
    """A TLS Certificate handshake record carrying a single DER cert."""
    entry = struct.pack(">I", len(der))[1:] + der
    cert_list = struct.pack(">I", len(entry))[1:] + entry
    handshake = b"\x0b" + struct.pack(">I", len(cert_list))[1:] + cert_list
    return b"\x16\x03\x03" + _u16(len(handshake)) + handshake


def _rsa_leaf_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")])
    now = datetime.datetime(2025, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# --- helpers -------------------------------------------------------------


def _ctx(sniff: SniffConfig | None = SniffConfig(),
         caps: set[Capability] | None = None) -> ScanContext:
    if caps is None:
        caps = {Capability.NET_RAW}
    return ScanContext(scan_id=1, mode="user", available_capabilities=caps, sniff=sniff)


def _run(frames: list[bytes]) -> list[Finding]:
    probe = NetSniffLive(frame_source=lambda cfg: frames)
    out: list[Finding] = []
    asyncio.run(probe.run(_ctx(), out.append))
    return out


# --- tests: parsing ------------------------------------------------------


def test_client_hello_advertised_group_low_confidence() -> None:
    frames = [_eth_ipv4_tcp(build_client_hello_tls12("example.com"))]
    findings = _run(frames)
    ch = [f for f in findings if f.evidence.get("record") == "client_hello"]
    assert ch, "expected an advertised client_hello finding"
    # secp256r1 / x25519 are classical KEX groups -> quantum-vulnerable.
    classical = [f for f in ch if f.classification is Classification.TINGGI]
    assert classical
    f = classical[0]
    assert f.evidence["advertised"] is True
    assert f.evidence["confidence"] == "low"
    assert f.severity is Severity.HIGH


def test_server_hello_negotiated_cipher_medium_confidence() -> None:
    # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    frames = [_eth_ipv4_tcp(_server_hello_record(0xC02F))]
    findings = _run(frames)
    sh = [f for f in findings if f.evidence.get("record") == "server_hello"]
    assert sh, "expected a negotiated server_hello finding"
    f = sh[0]
    assert f.evidence["confidence"] == "medium"
    assert f.classification is Classification.TINGGI  # classical ECDHE KEX
    assert f.evidence.get("advertised") is None


def test_certificate_rsa_leaf_high_confidence() -> None:
    frames = [_eth_ipv4_tcp(_certificate_record(_rsa_leaf_der()))]
    findings = _run(frames)
    certs = [f for f in findings if f.evidence.get("record") == "certificate"]
    assert certs, "expected a certificate finding"
    f = certs[0]
    assert f.evidence["confidence"] == "high"
    assert "RSA" in f.algorithm
    assert f.classification is Classification.TINGGI  # RSA sig — quantum-forgeable


def test_no_tls_emits_single_info() -> None:
    findings = _run([])
    assert len(findings) == 1
    f = findings[0]
    assert f.classification is Classification.INFO
    assert "no TLS handshakes observed" in f.title


def test_dedup_across_repeated_frames() -> None:
    frame = _eth_ipv4_tcp(_server_hello_record(0xC02F))
    findings = _run([frame, frame, frame])
    sh = [f for f in findings if f.evidence.get("record") == "server_hello"]
    assert len(sh) == 1  # deduped by (src, dst, dport, alg, kind)


# --- tests: applies() gating --------------------------------------------


def test_applies_false_when_sniff_none() -> None:
    probe = NetSniffLive(frame_source=lambda cfg: [])
    assert asyncio.run(probe.applies(_ctx(sniff=None))) is False


def test_applies_false_without_net_raw() -> None:
    probe = NetSniffLive(frame_source=lambda cfg: [])
    assert asyncio.run(probe.applies(_ctx(caps=set()))) is False


def test_applies_false_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pqcscan.probes.net_sniff_live.sys.platform", "darwin")
    probe = NetSniffLive(frame_source=lambda cfg: [])
    assert asyncio.run(probe.applies(_ctx())) is False


def test_applies_true_on_linux_with_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pqcscan.probes.net_sniff_live.sys.platform", "linux")
    probe = NetSniffLive(frame_source=lambda cfg: [])
    assert asyncio.run(probe.applies(_ctx())) is True


# --- tests: CLI ----------------------------------------------------------


def test_cli_lists_sniff_command() -> None:
    from click.testing import CliRunner

    from pqcscan.cli.main import cli
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "sniff" in result.output
