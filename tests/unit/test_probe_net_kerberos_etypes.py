"""Tests for net.kerberos.etypes (KDC encryption-type enumeration via AS-REQ)."""
import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_kerberos_etypes import (
    NetKerberosEtypes,
    build_as_req,
    classify_etype,
    parse_kdc_reply,
)


# --- tiny DER helpers to hand-build KDC replies (independent of the probe) --
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    body = b""
    while n:
        body = bytes((n & 0xFF,)) + body
        n >>= 8
    return bytes((0x80 | len(body),)) + body


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(val)) + val


def _int(n: int) -> bytes:
    body = bytes((n,)) if n else b"\x00"
    return _tlv(0x02, body)


def _ctx(n: int, val: bytes) -> bytes:
    return _tlv(0xA0 | n, val)


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _octet(val: bytes) -> bytes:
    return _tlv(0x04, val)


def _ctx_obj(target: str | None = None) -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(), server_target=target
    )


# --- (1) AS-REQ builder round-trip --------------------------------------
def test_build_as_req_structure():
    etypes = [18, 17, 23, 16]
    msg = build_as_req("EXAMPLE.COM", "probe", etypes)
    assert msg[0] == 0x6A  # [APPLICATION 10] AS-REQ
    # pvno=5 -> [1] INTEGER 5 ; msg-type=10 -> [2] INTEGER 10
    assert b"\xa1\x03\x02\x01\x05" in msg
    assert b"\xa2\x03\x02\x01\x0a" in msg
    # every requested etype is present as a small INTEGER inside the etype SEQUENCE
    for e in etypes:
        assert _int(e) in msg
    # the realm and the krbtgt sname component are carried as GeneralStrings
    assert b"EXAMPLE.COM" in msg
    assert b"krbtgt" in msg


# --- (2) parser: KRB-ERROR error code -----------------------------------
def test_parse_krb_error_code():
    # [APPLICATION 30] { SEQUENCE { [6] error-code = 25 (PREAUTH_REQUIRED) } }
    err = _tlv(0x7E, _seq(_ctx(6, _int(25))))
    out = parse_kdc_reply(err)
    assert out["msg_type"] == 30
    assert out["error_code"] == 25
    assert out["etypes"] == []


# --- (3) parser: ETYPE-INFO2 in KRB-ERROR e-data ------------------------
def test_parse_etype_info2_from_edata():
    etype_info2 = _seq(_seq(_ctx(0, _int(23))), _seq(_ctx(0, _int(18))))
    padata = _seq(_ctx(1, _int(19)), _ctx(2, _octet(etype_info2)))  # PA-ETYPE-INFO2
    edata = _octet(_seq(padata))  # METHOD-DATA inside the e-data OCTET STRING
    err = _tlv(0x7E, _seq(_ctx(6, _int(25)), _ctx(12, edata)))
    out = parse_kdc_reply(err)
    assert out["msg_type"] == 30
    assert out["etypes"] == [23, 18]


def test_parse_as_rep_enc_part_etype():
    enc = _seq(_ctx(0, _int(18)), _ctx(2, _octet(b"\x00")))  # EncryptedData
    rep = _tlv(0x6B, _seq(_ctx(6, enc)))  # [APPLICATION 11] AS-REP
    out = parse_kdc_reply(rep)
    assert out["msg_type"] == 11
    assert out["etypes"] == [18]


def test_parse_garbage_never_raises():
    for junk in (b"", b"\x00", b"\x7e\x80", b"\xff\xff\xff"):
        out = parse_kdc_reply(junk)
        assert out["msg_type"] is None
        assert out["etypes"] == []


# --- (4) etype -> classification map -------------------------------------
@pytest.mark.parametrize(
    ("etype", "expected"),
    [
        (1, Classification.SANGAT_TINGGI),   # des-cbc-crc
        (3, Classification.SANGAT_TINGGI),   # des-cbc-md5
        (23, Classification.SANGAT_TINGGI),  # rc4-hmac
        (24, Classification.SANGAT_TINGGI),  # export rc4
        (16, Classification.TINGGI),         # des3-cbc-sha1 (3DES)
        (17, Classification.SEDERHANA),      # aes128
        (19, Classification.SEDERHANA),      # aes128-sha256
        (18, Classification.RENDAH),         # aes256
        (20, Classification.RENDAH),         # aes256-sha384
        (99, Classification.INFO),           # unknown
    ],
)
def test_classify_etype(etype: int, expected: Classification):
    assert classify_etype(etype) is expected


# --- applies() -----------------------------------------------------------
@pytest.mark.asyncio
async def test_applies_requires_target():
    assert await NetKerberosEtypes(target="kdc:88").applies(_ctx_obj()) is True
    assert await NetKerberosEtypes().applies(_ctx_obj()) is False
    assert await NetKerberosEtypes().applies(_ctx_obj("kdc.example")) is True


def test_resolve_target_defaults_to_88():
    p = NetKerberosEtypes()
    assert p._resolve_target(_ctx_obj("kdc.example")) == ("kdc.example", 88)
    assert p._resolve_target(_ctx_obj("kdc.example:8888")) == ("kdc.example", 8888)
    assert p._resolve_target(_ctx_obj("kdc:notaport")) is None
    assert p._resolve_target(_ctx_obj(None)) is None


# --- run(): findings from a parsed reply ---------------------------------
@pytest.mark.asyncio
async def test_run_emits_finding_per_etype(monkeypatch):
    probe = NetKerberosEtypes(target="kdc:88")

    async def fake(host, port, realm, principal):
        return {"msg_type": 30, "etypes": [23, 18], "error_code": 25}

    monkeypatch.setattr(probe, "_query", fake)
    found: list = []
    await probe.run(_ctx_obj(), emit=lambda f: found.append(f))
    assert len(found) == 2
    by_etype = {f.evidence["etype"]: f for f in found}
    assert by_etype[23].classification is Classification.SANGAT_TINGGI
    assert by_etype[23].severity is Severity.CRIT
    assert by_etype[18].classification is Classification.RENDAH
    assert by_etype[18].severity is Severity.LOW


@pytest.mark.asyncio
async def test_run_emits_info_when_no_etypes_echoed(monkeypatch):
    probe = NetKerberosEtypes(target="kdc:88")

    async def fake(host, port, realm, principal):
        return {"msg_type": 30, "etypes": [], "error_code": 6}

    monkeypatch.setattr(probe, "_query", fake)
    found: list = []
    await probe.run(_ctx_obj(), emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert found[0].evidence["error_code"] == 6
    assert found[0].evidence["etypes_offered"]  # non-empty client-side exposure list


@pytest.mark.asyncio
async def test_run_on_closed_port_emits_nothing():
    # 127.0.0.1:1 is closed -> _query returns None -> no findings, no raise.
    probe = NetKerberosEtypes(target="127.0.0.1:1", timeout=2.0)
    found: list = []
    await probe.run(_ctx_obj(), emit=lambda f: found.append(f))
    assert found == []
