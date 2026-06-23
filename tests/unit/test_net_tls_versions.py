"""Tests for net.tls.versions (raw-TLS protocol-version sweep)."""
import struct

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_tls_versions import (
    NetTlsVersions,
    build_client_hello,
    detect_accept,
)


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _server_hello(version: int = 0x0303) -> bytes:
    """Hand-craft a minimal ServerHello (handshake type 0x02) — server ACCEPTED."""
    exts = b""
    body = (
        _u16(version) + bytes(32) + b"\x00"     # version, random, empty session_id
        + _u16(0x1301) + b"\x00"                # cipher_suite, compression
        + _u16(len(exts)) + exts
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + _u16(len(hs)) + hs


def _alert(desc: int = 0x28) -> bytes:
    """Hand-craft a TLS alert record (content type 0x15) — server REJECTED."""
    return b"\x15\x03\x03" + _u16(2) + bytes([0x02, desc])


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(), server_target=target
    )


# --- detect_accept -------------------------------------------------------

def test_detect_accept_on_server_hello():
    assert detect_accept(_server_hello()) is True


def test_detect_reject_on_alert():
    assert detect_accept(_alert()) is False


def test_detect_reject_on_empty():
    assert detect_accept(b"") is False


def test_detect_reject_on_truncated():
    assert detect_accept(b"\x16\x03\x03\x00") is False


def test_detect_reject_on_non_serverhello_handshake():
    # handshake record, but handshake type 0x0b (Certificate), not ServerHello.
    hs = b"\x0b" + bytes(3) + b""
    rec = b"\x16\x03\x03" + _u16(len(hs)) + hs
    assert detect_accept(rec) is False


# --- build_client_hello --------------------------------------------------

def test_build_legacy_version_for_tls12_and_below():
    for v in (0x0300, 0x0301, 0x0302, 0x0303):
        ch = build_client_hello(v)
        assert ch[0] == 0x16 and ch[1] == 0x03 and ch[2] == 0x01   # handshake record, TLS 1.0
        assert ch[5] == 0x01                                       # ClientHello handshake type
        assert struct.unpack(">H", ch[3:5])[0] == len(ch) - 5      # record length sane
        # ClientHello body starts after record(5) + hs_type(1) + hs_len(3) = 9
        assert struct.unpack(">H", ch[9:11])[0] == v               # legacy_version == target
        # supported_versions extension (0x002b) must be OMITTED for <= 1.2
        assert _u16(0x002B) not in ch


def test_build_tls13_uses_legacy_1_2_and_supported_versions():
    ch = build_client_hello(0x0304)
    assert struct.unpack(">H", ch[9:11])[0] == 0x0303             # legacy_version TLS 1.2
    # supported_versions extension present, advertising 0x0304
    assert _u16(0x002B) in ch
    assert b"\x02\x03\x04" in ch                                  # list len 2 + TLS 1.3
    # TLS 1.3 must carry a key_share extension (0x0033)
    assert _u16(0x0033) in ch


def test_build_with_sni():
    ch = build_client_hello(0x0303, "example.com")
    assert b"example.com" in ch
    assert _u16(0x0000) in ch                                    # server_name extension


# --- target resolution / applies ----------------------------------------

def test_resolve_target():
    p = NetTlsVersions()
    assert p._resolve_target(_ctx("host.example:8443")) == ("host.example", 8443)
    assert p._resolve_target(_ctx("host.example")) == ("host.example", 443)
    assert p._resolve_target(_ctx(None)) is None
    # Malformed targets must gate the probe off, not crash the scan
    # (applies() runs outside the runner's try/except).
    assert p._resolve_target(_ctx("host:notaport")) is None
    assert p._resolve_target(_ctx("host:80:443")) is None


def test_resolve_target_injected_overrides_ctx():
    p = NetTlsVersions(target="injected:9000")
    assert p._resolve_target(_ctx("ctx.example:443")) == ("injected", 9000)


@pytest.mark.asyncio
async def test_applies_requires_target():
    assert await NetTlsVersions(target="x:443").applies(_ctx()) is True
    assert await NetTlsVersions().applies(_ctx()) is False
    assert await NetTlsVersions().applies(_ctx("x:443")) is True


# --- run() with stubbed socket layer ------------------------------------

def _stub(probe: NetTlsVersions, accepted: dict[int, bool], monkeypatch):
    async def fake(host, port, version):
        return accepted.get(version, False)
    monkeypatch.setattr(probe, "_probe_version", fake)


@pytest.mark.asyncio
async def test_run_no_target_emits_nothing(monkeypatch):
    probe = NetTlsVersions()
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert found == []


@pytest.mark.asyncio
async def test_run_sslv3_accepted_is_high(monkeypatch):
    probe = NetTlsVersions(target="srv:443")
    _stub(probe, {0x0300: True, 0x0303: True, 0x0304: True}, monkeypatch)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    sslv3 = [f for f in found if f.algorithm == "SSL 3.0"]
    assert len(sslv3) == 1
    assert sslv3[0].classification is Classification.TINGGI
    assert sslv3[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_run_tls10_accepted_is_high(monkeypatch):
    probe = NetTlsVersions(target="srv:443")
    _stub(probe, {0x0301: True, 0x0304: True}, monkeypatch)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    tls10 = [f for f in found if f.algorithm == "TLS 1.0"]
    assert tls10[0].classification is Classification.TINGGI
    assert tls10[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_run_tls11_accepted_is_med(monkeypatch):
    probe = NetTlsVersions(target="srv:443")
    _stub(probe, {0x0302: True, 0x0304: True}, monkeypatch)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    tls11 = [f for f in found if f.algorithm == "TLS 1.1"]
    assert tls11[0].classification is Classification.SEDERHANA
    assert tls11[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_run_tls13_supported_is_info(monkeypatch):
    probe = NetTlsVersions(target="srv:443")
    _stub(probe, {0x0303: True, 0x0304: True}, monkeypatch)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    tls13 = [f for f in found if f.algorithm == "TLS 1.3"]
    assert len(tls13) == 1
    assert tls13[0].classification is Classification.INFO
    assert tls13[0].severity is Severity.INFO


@pytest.mark.asyncio
async def test_run_no_tls13_is_med_with_pqc_note(monkeypatch):
    probe = NetTlsVersions(target="srv:443")
    _stub(probe, {0x0303: True, 0x0304: False}, monkeypatch)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    tls13 = [f for f in found if f.algorithm == "TLS 1.3"]
    assert len(tls13) == 1
    assert tls13[0].classification is Classification.SEDERHANA
    assert tls13[0].severity is Severity.MED
    assert "no PQC-capable transport" in tls13[0].title
    assert "TLS 1.2" in tls13[0].evidence["supported"]


@pytest.mark.asyncio
async def test_run_modern_server_only_info(monkeypatch):
    # Only TLS 1.2 + 1.3 accepted: no HIGH/MED version findings, one INFO.
    probe = NetTlsVersions(target="srv:443")
    _stub(probe, {0x0303: True, 0x0304: True}, monkeypatch)
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
