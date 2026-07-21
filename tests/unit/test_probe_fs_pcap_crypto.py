"""Tests for fs.pcap.crypto — passive PCAP crypto extractor.

All fixtures are hand-built with `struct` (no dependency on the probe's own
parsers), so the test proves the probe reads the same bytes a real capture tool
would write: a classic-pcap / pcapng container wrapping an Ethernet/IPv4/TCP
frame whose payload is a minimal TLS or SSH handshake.
"""
from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_pcap_crypto import FsPcapCrypto

# --- byte fixture builders ----------------------------------------------


def _tls_client_hello(ciphers: list[int], groups: list[int] | None = None) -> bytes:
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"  # legacy_version, random, session_id(0)
    cs = b"".join(struct.pack(">H", c) for c in ciphers)
    body += struct.pack(">H", len(cs)) + cs
    body += b"\x01\x00"  # compression_methods: null
    exts = b""
    if groups:
        g = b"".join(struct.pack(">H", x) for x in groups)
        ext_body = struct.pack(">H", len(g)) + g
        exts += struct.pack(">H", 0x000A) + struct.pack(">H", len(ext_body)) + ext_body
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _tls_server_hello(cipher: int, version: int = 0x0303, group: int | None = None) -> bytes:
    body = struct.pack(">H", version) + b"\x00" * 32 + b"\x00"  # version, random, sid(0)
    body += struct.pack(">H", cipher) + b"\x00"  # cipher_suite + compression
    exts = b""
    if group is not None:
        ks = struct.pack(">H", group) + struct.pack(">H", 1) + b"\x00"  # group + keylen + key
        exts += struct.pack(">H", 0x0033) + struct.pack(">H", len(ks)) + ks
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def _ssh_kexinit(kex: list[str], hostkey: list[str]) -> bytes:
    def namelist(items: list[str]) -> bytes:
        s = ",".join(items).encode()
        return struct.pack(">I", len(s)) + s

    payload = bytes([20]) + b"\x00" * 16  # SSH_MSG_KEXINIT + cookie
    payload += namelist(kex) + namelist(hostkey)
    for _ in range(6):  # enc c2s/s2c, mac c2s/s2c, comp c2s/s2c
        payload += namelist([])
    for _ in range(2):  # languages c2s/s2c
        payload += namelist([])
    payload += b"\x00" + b"\x00\x00\x00\x00"  # first_kex_packet_follows + reserved
    pad = b"\x00" * 4
    pkt_len = 1 + len(payload) + len(pad)
    packet = struct.pack(">I", pkt_len) + bytes([len(pad)]) + payload + pad
    return b"SSH-2.0-TestServer\r\n" + packet


def _eth_ipv4_tcp(payload: bytes, sport: int = 40000, dport: int = 443) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 0, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
        socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"),
    )
    eth = b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00"
    return eth + ip + tcp


def _eth_ipv4_udp(payload: bytes, sport: int = 40000, dport: int = 443) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,   # proto 17 = UDP
        socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"),
    )
    eth = b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00"
    return eth + ip + udp


def _classic_pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for f in frames:
        out += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
    return out


def _pcapng_block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<I", btype) + struct.pack("<I", total) + body + struct.pack("<I", total)


def _pcapng(frames: list[bytes], linktype: int = 1, simple: bool = False) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)  # BOM, ver, section_len
    out = _pcapng_block(0x0A0D0D0A, shb_body)
    out += _pcapng_block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))  # IDB
    for f in frames:
        pad = (-len(f)) % 4
        if simple:
            body = struct.pack("<I", len(f)) + f + b"\x00" * pad  # SPB
            out += _pcapng_block(0x00000003, body)
        else:
            body = struct.pack("<IIIII", 0, 0, 0, len(f), len(f)) + f + b"\x00" * pad  # EPB
            out += _pcapng_block(0x00000006, body)
    return out


# --- harness ------------------------------------------------------------


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(),
                       scan_paths=[tmp_path])


async def _run(tmp_path: Path) -> list:
    found: list = []
    await FsPcapCrypto().run(_ctx(tmp_path), emit=found.append)
    return found


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# --- tests --------------------------------------------------------------


@pytest.mark.asyncio
async def test_classic_pcap_weak_tls_client_hello(tmp_path: Path):
    frame = _eth_ipv4_tcp(_tls_client_hello([0x000A]))  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    _write(tmp_path, "weak.pcap", _classic_pcap([frame]))
    found = await _run(tmp_path)
    suites = [f for f in found if f.evidence.get("proto") == "tls"]
    assert any(f.classification is Classification.SANGAT_TINGGI for f in suites)
    hit = next(f for f in suites if f.classification is Classification.SANGAT_TINGGI)
    assert "3DES" in hit.algorithm
    assert hit.severity is Severity.CRIT
    assert hit.evidence["src"] == "10.0.0.1:40000"
    assert hit.evidence["dst"] == "10.0.0.2:443"


@pytest.mark.asyncio
async def test_pcapng_enhanced_block_tls(tmp_path: Path):
    frame = _eth_ipv4_tcp(_tls_client_hello([0x000A]))
    _write(tmp_path, "weak.pcapng", _pcapng([frame]))
    found = await _run(tmp_path)
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_pcapng_simple_block_tls(tmp_path: Path):
    frame = _eth_ipv4_tcp(_tls_client_hello([0x000A]))
    _write(tmp_path, "simple.pcapng", _pcapng([frame], simple=True))
    found = await _run(tmp_path)
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_server_hello_modern_ecdhe_is_tinggi(tmp_path: Path):
    # ServerHello selecting TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 over TLS 1.2:
    # a modern AEAD suite, but ECDHE is quantum-vulnerable KEX -> TINGGI.
    frame = _eth_ipv4_tcp(_tls_server_hello(0xC02F, version=0x0303))
    _write(tmp_path, "sh.pcap", _classic_pcap([frame]))
    found = await _run(tmp_path)
    tls = [f for f in found if f.evidence.get("proto") == "tls"]
    assert tls, "expected a TLS finding"
    hit = next(f for f in tls if "ECDHE" in f.algorithm)
    assert hit.classification is Classification.TINGGI
    assert hit.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_pcqc_key_share_group_is_pqc_ready(tmp_path: Path):
    # ClientHello offering the hybrid X25519MLKEM768 group (0x11EC).
    frame = _eth_ipv4_tcp(_tls_client_hello([0x1301], groups=[0x11EC]))
    _write(tmp_path, "pqc.pcap", _classic_pcap([frame]))
    found = await _run(tmp_path)
    assert any(f.classification is Classification.PQC_READY for f in found)


@pytest.mark.asyncio
async def test_quic_initial_pqc_group_extracted(tmp_path: Path):
    # A QUIC Initial packet (UDP) whose encrypted ClientHello offers the hybrid
    # X25519MLKEM768 group — the probe decrypts the Initial and inventories it.
    from tests.unit.test_quic import _client_hello, build_quic_initial
    quic = build_quic_initial(_client_hello([0x001D, 0x11EC], [0x11EC]))
    frame = _eth_ipv4_udp(quic)
    _write(tmp_path, "quic.pcap", _classic_pcap([frame]))
    found = await _run(tmp_path)
    pqc = [f for f in found if f.algorithm == "X25519MLKEM768"]
    assert pqc, "expected the PQC group from the QUIC ClientHello"
    assert pqc[0].classification is Classification.PQC_READY
    assert pqc[0].evidence.get("proto") == "quic"


@pytest.mark.asyncio
async def test_ssh_kexinit(tmp_path: Path):
    payload = _ssh_kexinit(
        kex=["curve25519-sha256", "diffie-hellman-group14-sha256", "sntrup761x25519-sha512"],
        hostkey=["ssh-rsa", "ssh-ed25519"],
    )
    frame = _eth_ipv4_tcp(payload, dport=22)
    _write(tmp_path, "ssh.pcap", _classic_pcap([frame]))
    found = await _run(tmp_path)
    ssh = [f for f in found if f.evidence.get("proto") == "ssh"]
    algs = {f.algorithm: f.classification for f in ssh}
    assert algs.get("curve25519-sha256") is Classification.TINGGI
    assert algs.get("diffie-hellman-group14-sha256") is Classification.TINGGI
    assert algs.get("sntrup761x25519-sha512") is Classification.PQC_READY
    # ssh-rsa maps to RSA-2048 (< 3072-bit) -> SANGAT_TINGGI host key.
    assert algs.get("ssh-rsa") is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_random_bytes_no_findings_no_crash(tmp_path: Path):
    _write(tmp_path, "junk.pcap", b"\xde\xad\xbe\xef" * 64)
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_dedup_across_repeated_handshakes(tmp_path: Path):
    frame = _eth_ipv4_tcp(_tls_client_hello([0x000A]))
    _write(tmp_path, "dup.pcap", _classic_pcap([frame] * 50))
    found = await _run(tmp_path)
    threedes = [f for f in found if "3DES" in f.algorithm]
    assert len(threedes) == 1  # de-duped to a single (proto, endpoint, alg) row


@pytest.mark.asyncio
async def test_applies_true_with_scan_paths(tmp_path: Path):
    assert await FsPcapCrypto().applies(_ctx(tmp_path)) is True


@pytest.mark.asyncio
async def test_applies_false_without_scan_paths():
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await FsPcapCrypto().applies(ctx) is False


@pytest.mark.asyncio
async def test_non_pcap_file_ignored(tmp_path: Path):
    _write(tmp_path, "notes.txt", b"hello world, not a capture")
    assert await _run(tmp_path) == []
