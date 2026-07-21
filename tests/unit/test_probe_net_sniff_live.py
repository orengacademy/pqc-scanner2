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
    seq: int = 1,
) -> bytes:
    """Wrap a TCP payload in Ethernet II + IPv4 + TCP headers."""
    tcp = (
        _u16(sport) + _u16(dport)
        + struct.pack(">I", seq)       # seq
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


def _client_hello_pqc(groups: list[int], key_share: list[int]) -> bytes:
    """A TLS-record ClientHello with the given supported_groups (0x000a) and
    key_share (0x0033) group codes — for exercising the PQC key_share grading."""
    gl = b"".join(_u16(g) for g in groups)
    sg = _u16(0x000A) + _u16(len(gl) + 2) + _u16(len(gl)) + gl
    ks_entries = b"".join(_u16(g) + _u16(32) + b"\x11" * 32 for g in key_share)
    ks = _u16(0x0033) + _u16(len(ks_entries) + 2) + _u16(len(ks_entries)) + ks_entries
    exts = sg + ks
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + _u16(2) + b"\x13\x01"
            + b"\x01\x00" + _u16(len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def test_client_hello_pqc_key_share_offer_is_medium_confidence() -> None:
    # Client advertises x25519 (classical) + X25519MLKEM768 (0x11EC, PQC hybrid)
    # but sends a key_share only for the PQC hybrid — the stronger "actively
    # negotiating PQC" signal.
    frames = [_eth_ipv4_tcp(_client_hello_pqc([0x001D, 0x11EC], [0x11EC]))]
    findings = _run(frames)
    ch = [f for f in findings if f.evidence.get("record") == "client_hello"]
    pqc = [f for f in ch if f.algorithm == "X25519MLKEM768"]
    assert len(pqc) == 1, "PQC group emitted exactly once (deduped)"
    f = pqc[0]
    assert f.classification is Classification.PQC_READY
    assert f.evidence["confidence"] == "medium"
    assert f.evidence["key_share_offered"] is True
    assert f.evidence.get("advertised") is None  # key_share is stronger than advertised
    assert "offered key_share for" in f.title
    # The classical group, advertised only, stays low confidence.
    classical = [f for f in ch if f.algorithm == "x25519"]
    assert classical and classical[0].evidence["confidence"] == "low"
    assert classical[0].evidence["advertised"] is True


def test_client_hello_pqc_advertised_only_stays_low() -> None:
    # PQC hybrid listed in supported_groups but no key_share for it -> advertised.
    frames = [_eth_ipv4_tcp(_client_hello_pqc([0x11EC], []))]
    findings = _run(frames)
    pqc = [f for f in findings if f.algorithm == "X25519MLKEM768"]
    assert len(pqc) == 1
    assert pqc[0].evidence["confidence"] == "low"
    assert pqc[0].evidence["advertised"] is True
    assert pqc[0].evidence.get("key_share_offered") is None


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


def _split(payload: bytes, at: int, *, base_seq: int = 1) -> list[tuple[int, bytes]]:
    """Split a byte payload into two (seq, chunk) pieces at offset `at`."""
    return [(base_seq, payload[:at]), (base_seq + at, payload[at:])]


def test_multi_segment_client_hello_is_reassembled() -> None:
    # A ClientHello split across two TCP segments: neither half parses alone,
    # but the reassembled flow must yield the advertised-group finding.
    hello = build_client_hello_tls12("example.com")
    at = len(hello) // 2
    pieces = _split(hello, at)
    frames = [_eth_ipv4_tcp(chunk, seq=seq) for seq, chunk in pieces]
    # sanity: the first half alone is NOT a parseable hello
    assert not [
        f for f in _run([_eth_ipv4_tcp(hello[:at])])
        if f.evidence.get("record") == "client_hello"
    ]
    findings = _run(frames)
    ch = [f for f in findings if f.evidence.get("record") == "client_hello"]
    assert ch, "reassembled ClientHello should yield advertised-group findings"


def test_multi_segment_certificate_chain_is_reassembled() -> None:
    # A large Certificate record split across three TCP segments — the whole
    # point of reassembly (cert chains routinely span many packets).
    record = _certificate_record(_rsa_leaf_der())
    third = len(record) // 3
    pieces = [
        (1, record[:third]),
        (1 + third, record[third:2 * third]),
        (1 + 2 * third, record[2 * third:]),
    ]
    frames = [_eth_ipv4_tcp(chunk, seq=seq) for seq, chunk in pieces]
    findings = _run(frames)
    certs = [f for f in findings if f.evidence.get("record") == "certificate"]
    assert certs, "reassembled Certificate chain should yield a cert finding"
    assert certs[0].evidence["confidence"] == "high"
    assert "RSA" in certs[0].algorithm


def test_reassembly_handles_out_of_order_and_retransmit() -> None:
    # Segments delivered reversed, with a duplicate retransmit of the first —
    # sequence-ordered reassembly must still rebuild the ClientHello.
    hello = build_client_hello_tls12("example.com")
    at = len(hello) // 2
    (s0, c0), (s1, c1) = _split(hello, at)
    frames = [
        _eth_ipv4_tcp(c1, seq=s1),   # second half first
        _eth_ipv4_tcp(c0, seq=s0),   # first half second
        _eth_ipv4_tcp(c0, seq=s0),   # duplicate retransmit — must not corrupt
    ]
    findings = _run(frames)
    ch = [f for f in findings if f.evidence.get("record") == "client_hello"]
    assert ch, "out-of-order + retransmitted segments must still reassemble"


def test_reassembly_stops_at_gap() -> None:
    # A missing middle segment leaves only a partial prefix — the truncated
    # ClientHello must NOT be mis-parsed into a finding (gap ends the run).
    hello = build_client_hello_tls12("example.com")
    third = len(hello) // 3
    frames = [
        _eth_ipv4_tcp(hello[:third], seq=1),
        # middle segment (seq=1+third) is dropped
        _eth_ipv4_tcp(hello[2 * third:], seq=1 + 2 * third),
    ]
    findings = _run(frames)
    ch = [f for f in findings if f.evidence.get("record") == "client_hello"]
    assert not ch, "a gap must prevent a partial/mis-parsed hello finding"


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
