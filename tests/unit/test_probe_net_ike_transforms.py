"""Tests for net.ike.transforms — IKEv2 SA-transform enumeration.

The builder/parser are validated against constructed bytes (no live IKE
responder). SAr1 fixtures are hand-rolled with struct here, independently of
the module's own encoder, so the parser is tested against foreign bytes.
"""
import struct

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes._ike_packet import (
    EXCHANGE_IKE_SA_INIT,
    PAYLOAD_KE,
    PAYLOAD_NONCE,
    PAYLOAD_SA,
    build_ike_sa_init,
    classify_transform,
    extract_sa_payload,
    parse_sa_payload,
)
from pqcscan.probes.net_ike_transforms import NetIkeTransforms


# --- hand-rolled SAr1 encoders (deliberately not reusing the module's) ---
def _tf(tf_type: int, tf_id: int, key_len: int | None = None, *, more: bool = False) -> bytes:
    attrs = b""
    if key_len is not None:
        attrs = struct.pack(">HH", 0x800E, key_len)  # TV key-length attribute (type 14)
    body = struct.pack(">BBH", tf_type, 0, tf_id) + attrs
    length = 4 + len(body)
    return struct.pack(">BBH", 3 if more else 0, 0, length) + body


def _sar1(specs: list[tuple[int, int, int | None]], next_payload: int = 0) -> bytes:
    last = len(specs) - 1
    tf_block = b"".join(_tf(t, i, k, more=(idx < last)) for idx, (t, i, k) in enumerate(specs))
    prop_len = 8 + len(tf_block)
    prop = struct.pack(">BBHBBBB", 0, 0, prop_len, 1, 1, 0, len(specs)) + tf_block
    sa_len = 4 + len(prop)
    return struct.pack(">BBH", next_payload, 0, sa_len) + prop


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(), server_target=target)


# --- (1) builder: well-formed IKEv2 header + SA payload -------------------
def test_build_ike_sa_init_header_is_well_formed():
    pkt = build_ike_sa_init(initiator_spi=b"\x01" * 8, nonce=b"\x02" * 32)
    assert len(pkt) >= 28
    # 8-byte initiator SPI, 8-byte zero responder SPI.
    assert pkt[0:8] == b"\x01" * 8
    assert pkt[8:16] == b"\x00" * 8
    assert pkt[16] == PAYLOAD_SA               # next payload = SA (33)
    assert pkt[17] >> 4 == 2                    # major version 2
    assert pkt[18] == EXCHANGE_IKE_SA_INIT      # exchange type 34
    assert pkt[19] == 0x08                      # initiator flag
    assert struct.unpack(">I", pkt[24:28])[0] == len(pkt)  # length field == total


def test_build_ike_sa_init_payload_chaining():
    pkt = build_ike_sa_init(initiator_spi=b"\x03" * 8, nonce=b"\x04" * 32)
    # Walk the payload chain: SA -> KE -> Nonce -> none.
    seen = []
    next_payload = pkt[16]
    off = 28
    while next_payload != 0:
        nxt, _crit, plen = struct.unpack(">BBH", pkt[off:off + 4])
        seen.append(next_payload)
        next_payload = nxt
        off += plen
    assert seen == [PAYLOAD_SA, PAYLOAD_KE, PAYLOAD_NONCE]
    assert off == len(pkt)


def test_build_offers_classical_and_pqc_dh():
    pkt = build_ike_sa_init()
    sa = extract_sa_payload(pkt)
    assert sa is not None
    tfs = parse_sa_payload(sa)
    names = {t["name"] for t in tfs}
    assert "MODP-2048" in names or "ECP-256" in names   # classical DH offered
    assert "ML-KEM-768" in names                          # at least one PQC group
    assert "3DES" in names                                # weak cipher offered for detection


# --- (2) parse chosen {AES-CBC-256, PRF-SHA256, INTEG-SHA256, ECP-256} ----
def test_parse_sar1_modern_set():
    sar1 = _sar1([
        (1, 12, 256),   # ENCR AES-CBC-256
        (2, 5, None),   # PRF-HMAC-SHA256
        (3, 12, None),  # INTEG HMAC-SHA256-128
        (4, 19, None),  # DH ECP-256
    ])
    tfs = parse_sa_payload(sar1)
    assert [t["name"] for t in tfs] == [
        "AES-CBC-256", "PRF-HMAC-SHA256", "HMAC-SHA256-128", "ECP-256",
    ]
    assert [t["classification"] for t in tfs] == [
        Classification.RENDAH,       # AES-256
        Classification.SEDERHANA,    # SHA-256 PRF
        Classification.SEDERHANA,    # SHA-256 INTEG
        Classification.TINGGI,       # classical ECP-256 → Shor-broken
    ]
    assert tfs[0]["key_len"] == 256


# --- (3) parse legacy chosen {3DES, MODP-2048} → both TINGGI --------------
def test_parse_sar1_legacy_flags_weak():
    sar1 = _sar1([(1, 3, None), (4, 14, None)])  # 3DES + MODP-2048
    tfs = parse_sa_payload(sar1)
    assert [t["name"] for t in tfs] == ["3DES", "MODP-2048"]
    assert all(t["classification"] is Classification.TINGGI for t in tfs)


# --- (4) the transform → classification map ------------------------------
@pytest.mark.parametrize(("tf_type", "tf_id", "key_len", "expected"), [
    (1, 2, None, Classification.SANGAT_TINGGI),   # DES — broken
    (1, 3, None, Classification.TINGGI),          # 3DES — weak
    (1, 12, 128, Classification.SEDERHANA),       # AES-128
    (1, 12, 256, Classification.RENDAH),          # AES-256
    (1, 20, 256, Classification.RENDAH),          # AES-GCM-256
    (2, 2, None, Classification.TINGGI),          # PRF-HMAC-SHA1
    (2, 5, None, Classification.SEDERHANA),       # PRF-HMAC-SHA256
    (3, 14, None, Classification.RENDAH),         # HMAC-SHA512-256
    (4, 19, None, Classification.TINGGI),         # ECP-256 classical
    (4, 14, None, Classification.TINGGI),         # MODP-2048 classical
    (4, 31, None, Classification.TINGGI),         # Curve25519 classical
    (4, 36, None, Classification.PQC_READY),      # ML-KEM-768 PQC
    (4, 37, None, Classification.PQC_READY),      # ML-KEM-1024 PQC
])
def test_classify_transform_map(tf_type, tf_id, key_len, expected):
    assert classify_transform(tf_type, tf_id, key_len) is expected


# --- applies() ------------------------------------------------------------
@pytest.mark.asyncio
async def test_applies_true_with_target():
    assert await NetIkeTransforms(target="10.0.0.1").applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_true_with_ctx_server_target():
    assert await NetIkeTransforms().applies(_ctx(target="10.0.0.1:500")) is True


@pytest.mark.asyncio
async def test_applies_false_without_target():
    assert await NetIkeTransforms().applies(_ctx()) is False


# --- run() on a closed/silent UDP target ---------------------------------
@pytest.mark.asyncio
async def test_run_closed_target_emits_single_info():
    found: list = []
    probe = NetIkeTransforms(target="127.0.0.1:1", timeout=1.0)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    # Either no reply or an unparseable one → exactly one INFO, never a raise.
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert found[0].severity is Severity.INFO
    assert found[0].evidence["offered"]  # client-side posture recorded


@pytest.mark.asyncio
async def test_run_no_target_emits_nothing():
    found: list = []
    await NetIkeTransforms().run(_ctx(), emit=lambda f: found.append(f))
    assert found == []
