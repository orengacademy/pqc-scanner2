"""Hand-rolled IKEv2 (RFC 7296) IKE_SA_INIT builder + SA-payload parser.

Pure, dependency-free wire-format helpers so the ``net.ike.transforms`` probe
can be unit-tested against constructed bytes with no live IKE responder. The
builder emits an IKE_SA_INIT initiator request offering a broad transform set
(classical + a PQC ML-KEM DH group per RFC 9370); the parser decodes a
responder's SAr1 (its single chosen transform set) and classifies each
transform for post-quantum readiness.
"""
from __future__ import annotations

import os
import struct

from pqcscan.core.types import Classification

# --- IKEv2 header / exchange constants (RFC 7296 §3.1) -------------------
IKE_VERSION = 0x20  # major 2, minor 0
EXCHANGE_IKE_SA_INIT = 34
FLAG_INITIATOR = 0x08

# Payload type numbers (RFC 7296 §3.2).
PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40

# Proposal substructure (RFC 7296 §3.3).
PROTO_IKE = 1

# Transform types (RFC 7296 §3.3.2).
T_ENCR = 1
T_PRF = 2
T_INTEG = 3
T_DH = 4

_TYPE_NAMES: dict[int, str] = {
    T_ENCR: "ENCR",
    T_PRF: "PRF",
    T_INTEG: "INTEG",
    T_DH: "DH",
}

# Transform attribute: key length (RFC 7296 §3.3.5), TV-encoded.
ATTR_KEY_LENGTH = 14

# --- Transform ID → friendly name tables (IANA IKEv2 registries) ---------
_ENCR_NAMES: dict[int, str] = {
    2: "DES",           # ENCR_DES — broken
    3: "3DES",          # ENCR_3DES — weak
    11: "NULL",         # ENCR_NULL
    12: "AES-CBC",      # ENCR_AES_CBC
    13: "AES-CTR",      # ENCR_AES_CTR
    20: "AES-GCM-16",   # ENCR_AES_GCM_16
    28: "CHACHA20-POLY1305",
}
_PRF_NAMES: dict[int, str] = {
    1: "PRF-HMAC-MD5",
    2: "PRF-HMAC-SHA1",
    5: "PRF-HMAC-SHA256",
    6: "PRF-HMAC-SHA384",
    7: "PRF-HMAC-SHA512",
}
_INTEG_NAMES: dict[int, str] = {
    0: "NONE",
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    12: "HMAC-SHA256-128",
    13: "HMAC-SHA384-192",
    14: "HMAC-SHA512-256",
}
# All classical DH groups are Shor-vulnerable; RFC 9370 ML-KEM groups are PQC.
_DH_NAMES: dict[int, str] = {
    1: "MODP-768",
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    31: "Curve25519",
    32: "Curve448",
    35: "ML-KEM-512",
    36: "ML-KEM-768",
    37: "ML-KEM-1024",
}
# RFC 9370 additional key-exchange (ML-KEM) DH group IDs → PQC-ready.
_PQC_DH_IDS: frozenset[int] = frozenset({35, 36, 37})

_TF_NAME_TABLES: dict[int, dict[int, str]] = {
    T_ENCR: _ENCR_NAMES,
    T_PRF: _PRF_NAMES,
    T_INTEG: _INTEG_NAMES,
    T_DH: _DH_NAMES,
}


def transform_name(tf_type: int, tf_id: int, key_len: int | None = None) -> str:
    """Friendly name for a (type, id) transform, appending an AES key length."""
    base = _TF_NAME_TABLES.get(tf_type, {}).get(tf_id)
    if base is None:
        type_name = _TYPE_NAMES.get(tf_type, f"TYPE{tf_type}")
        return f"{type_name}-ID{tf_id}"
    if tf_type == T_ENCR and key_len is not None and base.startswith("AES"):
        return f"{base}-{key_len}"
    return base


def classify_transform(tf_type: int, tf_id: int, key_len: int | None = None) -> Classification:
    """Map a negotiated IKE transform to a PQC threat classification.

    DES → SANGAT_TINGGI, 3DES / classical DH / SHA-1 MAC → TINGGI,
    AES-128 / SHA-256 MAC → SEDERHANA, AES-192+/SHA-384+ MAC → RENDAH,
    RFC 9370 ML-KEM DH group → PQC_READY, anything unknown → INFO.
    """
    if tf_type == T_ENCR:
        if tf_id == 2:            # DES — classically broken
            return Classification.SANGAT_TINGGI
        if tf_id == 3:            # 3DES — weak (64-bit block, meet-in-the-middle)
            return Classification.TINGGI
        if tf_id in (12, 13, 20):  # AES CBC / CTR / GCM — Grover-weakened by key size
            return Classification.RENDAH if key_len is not None and key_len >= 192 else Classification.SEDERHANA
        if tf_id == 28:           # ChaCha20-Poly1305 — 256-bit key
            return Classification.RENDAH
        return Classification.INFO
    if tf_type == T_DH:
        if tf_id in _PQC_DH_IDS:
            return Classification.PQC_READY
        if tf_id in _DH_NAMES:    # classical MODP / ECP / Curve — Shor-broken
            return Classification.TINGGI
        return Classification.INFO
    if tf_type in (T_PRF, T_INTEG):
        name = transform_name(tf_type, tf_id)
        if "MD5" in name or "SHA1" in name:
            return Classification.TINGGI
        if "SHA256" in name:
            return Classification.SEDERHANA
        if "SHA384" in name or "SHA512" in name:
            return Classification.RENDAH
        return Classification.INFO
    return Classification.INFO


def describe_transform(tf_type: int, tf_id: int, key_len: int | None = None) -> dict:
    """Return {type, id, name, key_len, classification} for one transform."""
    return {
        "type": tf_type,
        "id": tf_id,
        "key_len": key_len,
        "name": transform_name(tf_type, tf_id, key_len),
        "classification": classify_transform(tf_type, tf_id, key_len),
    }


# --- Wire-format encoders -------------------------------------------------
def _transform(tf_type: int, tf_id: int, key_len: int | None, *, more: bool) -> bytes:
    """Encode one Transform substructure (RFC 7296 §3.3.2)."""
    attrs = b""
    if key_len is not None:
        # TV-format attribute: high bit set marks a 2-byte value follows.
        attrs = struct.pack(">HH", 0x8000 | ATTR_KEY_LENGTH, key_len)
    body = struct.pack(">BxH", tf_type, tf_id) + attrs  # type, reserved, id
    length = 4 + len(body)
    first = 3 if more else 0  # 3 = more transforms follow, 0 = last
    return struct.pack(">BxH", first, length) + body


def _transforms_block(specs: list[tuple[int, int, int | None]]) -> bytes:
    """Encode a flat list of (type, id, key_len); last one flagged as final."""
    last = len(specs) - 1
    return b"".join(
        _transform(t, i, k, more=(idx < last)) for idx, (t, i, k) in enumerate(specs)
    )


def _proposal(prop_num: int, specs: list[tuple[int, int, int | None]]) -> bytes:
    """Encode a single Proposal substructure (RFC 7296 §3.3), IKE, no SPI."""
    tf_block = _transforms_block(specs)
    length = 8 + len(tf_block)  # 8-byte proposal header, SPI size 0
    header = struct.pack(">BxHBBBB", 0, length, prop_num, PROTO_IKE, 0, len(specs))
    return header + tf_block


def build_sa_payload(specs: list[tuple[int, int, int | None]], next_payload: int) -> bytes:
    """Encode an SA payload carrying one proposal of the given transforms."""
    body = _proposal(1, specs)
    length = 4 + len(body)
    return struct.pack(">BxH", next_payload, length) + body


def _ke_payload(dh_group: int, ke_data: bytes, next_payload: int) -> bytes:
    body = struct.pack(">HH", dh_group, 0) + ke_data
    length = 4 + len(body)
    return struct.pack(">BxH", next_payload, length) + body


def _nonce_payload(nonce: bytes, next_payload: int) -> bytes:
    length = 4 + len(nonce)
    return struct.pack(">BxH", next_payload, length) + nonce


# The broad proposal we offer: multiple ENCR/PRF/INTEG/DH incl. classical
# groups and one PQC ML-KEM group (id 36) per RFC 9370.
_OFFERED_SPECS: list[tuple[int, int, int | None]] = [
    (T_ENCR, 20, 256),   # AES-GCM-16-256
    (T_ENCR, 12, 256),   # AES-CBC-256
    (T_ENCR, 12, 128),   # AES-CBC-128
    (T_ENCR, 3, None),   # 3DES (weak — offered to detect legacy responders)
    (T_PRF, 7, None),    # PRF-HMAC-SHA512
    (T_PRF, 6, None),    # PRF-HMAC-SHA384
    (T_PRF, 5, None),    # PRF-HMAC-SHA256
    (T_PRF, 2, None),    # PRF-HMAC-SHA1
    (T_INTEG, 14, None),  # HMAC-SHA512-256
    (T_INTEG, 13, None),  # HMAC-SHA384-192
    (T_INTEG, 12, None),  # HMAC-SHA256-128
    (T_INTEG, 2, None),   # HMAC-SHA1-96
    (T_DH, 36, None),    # ML-KEM-768 (PQC, RFC 9370)
    (T_DH, 31, None),    # Curve25519
    (T_DH, 21, None),    # ECP-521
    (T_DH, 20, None),    # ECP-384
    (T_DH, 19, None),    # ECP-256
    (T_DH, 15, None),    # MODP-3072
    (T_DH, 14, None),    # MODP-2048
]
# KE payload carries data sized for MODP-2048 (group 14): 2048-bit = 256 bytes.
_KE_GROUP = 14
_KE_LEN = 256


def offered_transforms() -> list[dict]:
    """The transforms this probe offers, described + classified (client posture)."""
    return [describe_transform(t, i, k) for (t, i, k) in _OFFERED_SPECS]


def build_ike_sa_init(initiator_spi: bytes | None = None, nonce: bytes | None = None) -> bytes:
    """Build a full IKE_SA_INIT initiator request: HDR + SAi1 + KEi + Ni."""
    initiator_spi = initiator_spi if initiator_spi is not None else os.urandom(8)
    nonce = nonce if nonce is not None else os.urandom(32)
    ke_data = b"\x00" * _KE_LEN

    sa = build_sa_payload(_OFFERED_SPECS, next_payload=PAYLOAD_KE)
    ke = _ke_payload(_KE_GROUP, ke_data, next_payload=PAYLOAD_NONCE)
    ni = _nonce_payload(nonce, next_payload=PAYLOAD_NONE)
    payloads = sa + ke + ni

    header = struct.pack(
        ">8s8sBBBBII",
        initiator_spi,
        b"\x00" * 8,          # responder SPI unknown in the first request
        PAYLOAD_SA,           # next payload
        IKE_VERSION,
        EXCHANGE_IKE_SA_INIT,
        FLAG_INITIATOR,
        0,                    # message ID
        28 + len(payloads),   # total length
    )
    return header + payloads


# --- Wire-format decoders -------------------------------------------------
def _attr_key_length(attrs: bytes) -> int | None:
    """Scan transform attributes for a key-length (type 14) value."""
    i = 0
    while i + 4 <= len(attrs):
        af_type = struct.unpack(">H", attrs[i:i + 2])[0]
        atype = af_type & 0x7FFF
        if af_type & 0x8000:  # TV: 2-byte value inline
            value = int(struct.unpack(">H", attrs[i + 2:i + 4])[0])
            i += 4
            if atype == ATTR_KEY_LENGTH:
                return value
        else:                 # TLV: length-prefixed value
            alen = struct.unpack(">H", attrs[i + 2:i + 4])[0]
            i += 4 + alen
    return None


def parse_sa_payload(data: bytes) -> list[dict]:
    """Parse an SA payload (SAr1) → list of chosen transforms.

    ``data`` starts at the SA payload's 4-byte generic payload header. Decodes
    the first proposal (a responder returns exactly one chosen proposal) and
    returns one dict per transform: {type, id, name, key_len, classification}.
    Malformed input yields whatever parsed cleanly before the fault.
    """
    results: list[dict] = []
    if len(data) < 8:
        return results
    # Skip the 4-byte generic payload header; first proposal follows.
    off = 4
    if off + 8 > len(data):
        return results
    _first, prop_len = struct.unpack(">BxH", data[off:off + 4])
    _prop_num, protocol, spi_size, num_tf = struct.unpack(">BBBB", data[off + 4:off + 8])
    if protocol != PROTO_IKE:
        # Not an IKE proposal; still attempt to decode transforms below.
        pass
    t_off = off + 8 + spi_size
    prop_end = min(off + prop_len, len(data)) if prop_len >= 8 else len(data)
    for _ in range(num_tf):
        if t_off + 8 > len(data):
            break
        _more, tf_len = struct.unpack(">BxH", data[t_off:t_off + 4])
        tf_type, tf_id = struct.unpack(">BxH", data[t_off + 4:t_off + 8])
        if tf_len < 8 or t_off + tf_len > len(data) or t_off >= prop_end:
            break
        attrs = data[t_off + 8:t_off + tf_len]
        key_len = _attr_key_length(attrs)
        results.append(describe_transform(tf_type, tf_id, key_len))
        t_off += tf_len
    return results


def extract_sa_payload(msg: bytes) -> bytes | None:
    """Walk an IKEv2 message's payload chain and return the SA payload bytes."""
    if len(msg) < 28:
        return None
    next_payload = msg[16]
    off = 28
    while next_payload != PAYLOAD_NONE and off + 4 <= len(msg):
        nxt, _crit, plen = struct.unpack(">BBH", msg[off:off + 4])
        if plen < 4 or off + plen > len(msg):
            return None
        if next_payload == PAYLOAD_SA:
            return msg[off:off + plen]
        next_payload = nxt
        off += plen
    return None
