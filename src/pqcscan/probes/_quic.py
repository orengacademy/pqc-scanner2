"""QUIC Initial-packet decryption — reach the TLS ClientHello inside QUIC.

QUIC (RFC 9000) runs the TLS 1.3 handshake, but the ClientHello is carried in a
CRYPTO frame inside an *Initial* packet that is AEAD-protected with keys derived
from the Destination Connection ID via HKDF (RFC 9001). No FOSS PQC scanner
reaches into QUIC; this module does, so `supported_groups` / `key_share` (and
thus offered PQC/hybrid groups) can be inventoried from QUIC traffic the same way
they already are for TLS-over-TCP.

The protection keys are *public* (derived from the on-the-wire DCID + a
version-specific fixed salt), so this is passive observation, not an attack.

Scope: client Initial packets for QUIC v1 (RFC 9001) and v2 (RFC 9369), AEAD
AES-128-GCM with AES-128-ECB header protection (the only Initial ciphersuite).
Pure `cryptography` + stdlib; reuses the project's TLS 1.3 HKDF.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcscan.probes._tls13_keyschedule import hkdf_expand_label, hkdf_extract

# version number -> (initial_salt, key/iv/hp label prefix)
_V1 = 0x00000001
_V2 = 0x6B3343CF
_VERSIONS: dict[int, tuple[bytes, str]] = {
    _V1: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), "quic"),
    _V2: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), "quicv2"),
}
# v1 Initial long-header type is 0b00; v2 remaps Initial to 0b01 (RFC 9369 §3.2).
_INITIAL_TYPE = {_V1: 0, _V2: 1}
_SAMPLE_LEN = 16
_MAX_QUIC = 1 << 16


def derive_initial_keys(dcid: bytes, version: int) -> tuple[bytes, bytes, bytes] | None:
    """(key, iv, hp) for the CLIENT Initial keys, or None for an unknown version."""
    entry = _VERSIONS.get(version)
    if entry is None:
        return None
    salt, pfx = entry
    initial_secret = hkdf_extract(salt, dcid)
    cis = hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = hkdf_expand_label(cis, f"{pfx} key", b"", 16)
    iv = hkdf_expand_label(cis, f"{pfx} iv", b"", 12)
    hp = hkdf_expand_label(cis, f"{pfx} hp", b"", 16)
    return key, iv, hp


def _varint(buf: bytes, off: int) -> tuple[int, int] | None:
    """Decode a QUIC variable-length integer (RFC 9000 §16). Returns (value, next_off)."""
    if off >= len(buf):
        return None
    prefix = buf[off] >> 6
    length = 1 << prefix
    if off + length > len(buf):
        return None
    val = buf[off] & 0x3F
    for i in range(1, length):
        val = (val << 8) | buf[off + i]
    return val, off + length


def _aes_ecb_block(hp_key: bytes, sample: bytes) -> bytes:
    enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


def _reassemble_crypto(frames: bytes) -> bytes | None:
    """Reassemble CRYPTO-frame data (RFC 9000 §19.6) into the handshake stream.

    Only the frame types that appear in an Initial before/around the ClientHello
    are handled: PADDING, PING, ACK, CRYPTO. An unrecognized frame stops parsing
    (the ClientHello is normally a single CRYPTO frame at offset 0)."""
    chunks: dict[int, bytes] = {}
    off = 0
    n = len(frames)
    while off < n:
        ftype = frames[off]
        if ftype == 0x00 or ftype == 0x01:  # PADDING / PING
            off += 1
            continue
        if ftype in (0x02, 0x03):  # ACK — skip its fields
            off += 1
            for _ in range(4):  # Largest Ack, ACK Delay, Range Count, First Range
                r = _varint(frames, off)
                if r is None:
                    return _join(chunks)
                _, off = r
            continue
        if ftype == 0x06:  # CRYPTO
            o = _varint(frames, off + 1)
            if o is None:
                break
            c_off, p = o
            ln = _varint(frames, p)
            if ln is None:
                break
            c_len, p = ln
            chunks[c_off] = frames[p:p + c_len]
            off = p + c_len
            continue
        break  # unknown frame — stop
    return _join(chunks)


def _join(chunks: dict[int, bytes]) -> bytes | None:
    if not chunks:
        return None
    out = bytearray()
    for offset in sorted(chunks):
        if offset != len(out):
            break  # gap — return the contiguous prefix (enough for the ClientHello)
        out += chunks[offset]
    return bytes(out) or None


def extract_client_hello(udp_payload: bytes) -> bytes | None:
    """From a UDP payload that is a QUIC client Initial packet, decrypt and
    return the raw TLS handshake bytes (the ClientHello, starting 0x01), or None
    if it is not a decryptable Initial packet."""
    b = udp_payload
    if not b or not (b[0] & 0x80) or len(b) > _MAX_QUIC or len(b) < 7:
        return None
    version = int.from_bytes(b[1:5], "big")
    entry = _VERSIONS.get(version)
    if entry is None:
        return None
    if ((b[0] & 0x30) >> 4) != _INITIAL_TYPE[version]:
        return None  # not an Initial packet
    try:
        off = 5
        dcid_len = b[off]
        off += 1
        dcid = b[off:off + dcid_len]
        off += dcid_len
        scid_len = b[off]
        off += 1 + scid_len
        tok = _varint(b, off)
        if tok is None:
            return None
        token_len, off = tok
        off += token_len
        ln = _varint(b, off)
        if ln is None:
            return None
        length, pn_offset = ln
    except IndexError:
        return None

    keys = derive_initial_keys(dcid, version)
    if keys is None:
        return None
    key, iv, hp = keys

    sample = b[pn_offset + 4:pn_offset + 4 + _SAMPLE_LEN]
    if len(sample) < _SAMPLE_LEN:
        return None
    mask = _aes_ecb_block(hp, sample)
    first = b[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    if pn_offset + pn_len > len(b):
        return None
    pn_bytes = bytes(b[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    pn = int.from_bytes(pn_bytes, "big")

    header = bytes([first]) + b[1:pn_offset] + pn_bytes
    payload_end = pn_offset + length
    ciphertext = b[pn_offset + pn_len:payload_end]
    if len(ciphertext) < 16:  # needs at least the GCM tag
        return None
    nonce = bytes(iv[i] ^ (pn.to_bytes(12, "big")[i]) for i in range(12))
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception:  # InvalidTag / malformed — not a valid Initial we can read
        return None
    return _reassemble_crypto(plaintext)
