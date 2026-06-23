"""Tests for net.tls.kex_groups (raw-TLS KEX-group enumeration)."""
import struct

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_tls_kex_groups import (
    NetTlsKexGroups,
    build_client_hello,
    parse_server_hello,
)


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _server_hello(group_code: int, *, hrr: bool = False) -> bytes:
    """Hand-craft a ServerHello (or HelloRetryRequest) selecting a group."""
    exts = _u16(0x002B) + _u16(2) + _u16(0x0304)            # supported_versions: TLS 1.3
    ks_body = _u16(group_code) if hrr else _u16(group_code) + _u16(32) + bytes(32)
    exts += _u16(0x0033) + _u16(len(ks_body)) + ks_body     # key_share (selected group)
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"                   # version, random, empty session_id
        + _u16(0x1301) + b"\x00"                            # cipher_suite, compression
        + _u16(len(exts)) + exts
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + _u16(len(hs)) + hs


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(), server_target=target
    )


def test_parse_classical_group():
    r = parse_server_hello(_server_hello(0x001D))
    assert r is not None
    assert r["group_name"] == "x25519"
    assert r["is_pqc"] is False
    assert r["version"] == 0x0304
    assert r["cipher"] == 0x1301


def test_parse_pqc_hybrid_in_hrr():
    # HelloRetryRequest carries the group with no key (group-only key_share).
    r = parse_server_hello(_server_hello(0x11EC, hrr=True))
    assert r["group_name"] == "X25519MLKEM768"
    assert r["is_pqc"] is True


def test_parse_unknown_group_code():
    r = parse_server_hello(_server_hello(0x4242))
    assert r["group_name"].startswith("unknown-0x4242")
    assert r["is_pqc"] is False


def test_parse_non_handshake_is_none():
    # A TLS alert record (content type 0x15) is not a ServerHello.
    assert parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28") is None
    assert parse_server_hello(b"") is None


def test_build_client_hello_structure():
    ch = build_client_hello()
    assert ch[0] == 0x16 and ch[1] == 0x03 and ch[2] == 0x01   # handshake record, TLS 1.0
    assert ch[5] == 0x01                                       # ClientHello handshake type
    # record length matches the remaining bytes
    assert struct.unpack(">H", ch[3:5])[0] == len(ch) - 5
    # offers the hybrid X25519MLKEM768 group (0x11ec) and an empty key_share
    assert b"\x11\xec" in ch
    assert _u16(0x0033) + _u16(0x0002) + _u16(0x0000) in ch


def test_build_client_hello_with_sni():
    ch = build_client_hello("example.com")
    assert b"example.com" in ch
    assert _u16(0x0000) in ch                                  # server_name extension


def test_resolve_target():
    p = NetTlsKexGroups()
    assert p._resolve_target(_ctx("host.example:8443")) == ("host.example", 8443)
    assert p._resolve_target(_ctx("host.example")) == ("host.example", 443)
    assert p._resolve_target(_ctx(None)) is None
    # Malformed targets gate off safely (applies() runs outside runner try/except).
    assert p._resolve_target(_ctx("host:notaport")) is None
    assert p._resolve_target(_ctx("host:80:443")) is None


@pytest.mark.asyncio
async def test_run_emits_pqc_finding(monkeypatch):
    probe = NetTlsKexGroups(target="srv:443")

    async def fake(host, port):
        return {"version": 0x0304, "cipher": 0x1301, "group_code": 0x11EC,
                "group_name": "X25519MLKEM768", "is_pqc": True}
    monkeypatch.setattr(probe, "_handshake", fake)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.PQC_READY
    assert found[0].severity is Severity.INFO


@pytest.mark.asyncio
async def test_run_emits_classical_hndl_finding(monkeypatch):
    probe = NetTlsKexGroups(target="srv:443")

    async def fake(host, port):
        return {"version": 0x0304, "cipher": 0x1301, "group_code": 0x001D,
                "group_name": "x25519", "is_pqc": False}
    monkeypatch.setattr(probe, "_handshake", fake)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED
    assert "harvest-now-decrypt-later" in found[0].title


@pytest.mark.asyncio
async def test_applies_requires_target():
    assert await NetTlsKexGroups(target="x:443").applies(_ctx()) is True
    assert await NetTlsKexGroups().applies(_ctx()) is False
    assert await NetTlsKexGroups().applies(_ctx("x:443")) is True
