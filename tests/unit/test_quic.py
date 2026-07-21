"""Tests for _quic — QUIC Initial-packet decryption to reach the ClientHello.

Correctness is anchored two ways: (1) the client-key derivation is checked
against the RFC 9001 Appendix A.1 test vector (DCID 8394c8f03e515708); (2) a
full build→decrypt round-trip recovers a crafted ClientHello (proving header-
protection removal + AEAD + CRYPTO-frame reassembly).
"""
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcscan.probes import _quic
from pqcscan.probes._quic import _V1, derive_initial_keys, extract_client_hello

_RFC_DCID = bytes.fromhex("8394c8f03e515708")


def _enc_varint(v: int) -> bytes:
    if v < 64:
        return bytes([v])
    if v < 16384:
        return bytes([0x40 | (v >> 8), v & 0xFF])
    return bytes([0x80 | (v >> 24), (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def build_quic_initial(handshake: bytes, dcid: bytes = _RFC_DCID,
                       version: int = _V1) -> bytes:
    """Build a QUIC (client) Initial packet carrying `handshake` in a CRYPTO
    frame at offset 0 — the inverse of extract_client_hello."""
    key, iv, hp = derive_initial_keys(dcid, version)
    crypto = b"\x06\x00" + _enc_varint(len(handshake)) + handshake
    plaintext = crypto + b"\x00" * max(0, 200 - len(crypto))  # pad for HP sample
    pn_bytes = b"\x00"
    # long header + fixed bit; Initial type per version (v1=0, v2=1); PN length 1
    first = 0xC0 | (_quic._INITIAL_TYPE[version] << 4)
    hdr = (bytes([first]) + struct.pack(">I", version)
           + bytes([len(dcid)]) + dcid + b"\x00" + b"\x00")  # scid_len=0, token_len=0
    length_enc = _enc_varint(len(pn_bytes) + len(plaintext) + 16)
    header = hdr + length_enc + pn_bytes
    nonce = bytes(iv[i] ^ (0).to_bytes(12, "big")[i] for i in range(12))
    ct = AESGCM(key).encrypt(nonce, plaintext, header)
    sample = ct[3:19]  # pn_offset+4, pn is 1 byte → ct index 3
    mask = _quic._aes_ecb_block(hp, sample)
    return (bytes([first ^ (mask[0] & 0x0F)]) + struct.pack(">I", version)
            + bytes([len(dcid)]) + dcid + b"\x00" + b"\x00" + length_enc
            + bytes([pn_bytes[0] ^ mask[1]]) + ct)


def _client_hello(groups, key_share):
    gl = b"".join(struct.pack(">H", g) for g in groups)
    sg = struct.pack(">H", 0x000A) + struct.pack(">H", len(gl) + 2) + struct.pack(">H", len(gl)) + gl
    kse = b"".join(struct.pack(">H", g) + struct.pack(">H", 32) + b"\x11" * 32 for g in key_share)
    kss = struct.pack(">H", 0x0033) + struct.pack(">H", len(kse) + 2) + struct.pack(">H", len(kse)) + kse
    exts = sg + kss
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


def test_rfc9001_a1_client_key_derivation():
    # RFC 9001 Appendix A.1 — the canonical QUIC v1 client Initial keys.
    key, iv, hp = derive_initial_keys(_RFC_DCID, _V1)
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_roundtrip_recovers_client_hello():
    ch = _client_hello([0x001D, 0x11EC], [0x11EC])
    packet = build_quic_initial(ch)
    assert extract_client_hello(packet) == ch


def test_roundtrip_quic_v2():
    ch = _client_hello([0x11EC], [0x11EC])
    packet = build_quic_initial(ch, version=_quic._V2)
    assert extract_client_hello(packet) == ch


def test_non_quic_payloads_return_none():
    assert extract_client_hello(b"") is None
    assert extract_client_hello(b"\x16\x03\x01\x00\x10") is None      # a TLS record, short header
    assert extract_client_hello(b"\x40" + b"\x00" * 40) is None       # short header (bit 7 clear)
    # long header but unknown version
    assert extract_client_hello(b"\xc0\xde\xad\xbe\xef" + b"\x00" * 40) is None


def test_corrupted_initial_returns_none():
    ch = _client_hello([0x11EC], [0x11EC])
    packet = bytearray(build_quic_initial(ch))
    packet[-1] ^= 0xFF  # corrupt the AEAD tag
    assert extract_client_hello(bytes(packet)) is None
