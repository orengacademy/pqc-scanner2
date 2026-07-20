"""TLS 1.3 key schedule (RFC 8446 §7.1) — pure, importable, no socket I/O.

This module implements just enough of the TLS 1.3 key schedule to derive the
*handshake* traffic keys from an (EC)DHE shared secret and the
ClientHello…ServerHello transcript, then open (AEAD-decrypt) the server's
encrypted handshake records. Everything here is a pure function of its inputs,
so it can be checked byte-for-byte against the RFC 8448 §3 test vectors without
touching the network (see tests/unit/test_tls13_keyschedule.py).

Key schedule (the part we need):

        0 -> HKDF-Extract = Early Secret
               |
               v
        Derive-Secret(., "derived", "")
               |
    (EC)DHE -> HKDF-Extract = Handshake Secret
               |
               +-> Derive-Secret(., "c hs traffic", CH..SH) = client_hs_secret
               +-> Derive-Secret(., "s hs traffic", CH..SH) = server_hs_secret

    traffic key = HKDF-Expand-Label(secret, "key", "", key_len)
    traffic iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# cipher_suite code -> (hash name, AEAD key length, is_chacha)
CIPHER_SUITES: dict[int, tuple[str, int, bool]] = {
    0x1301: ("sha256", 16, False),  # TLS_AES_128_GCM_SHA256
    0x1302: ("sha384", 32, False),  # TLS_AES_256_GCM_SHA384
    0x1303: ("sha256", 32, True),   # TLS_CHACHA20_POLY1305_SHA256
}


def _digest_size(hash_name: str) -> int:
    return hashlib.new(hash_name).digest_size


def transcript_hash(messages: bytes, hash_name: str = "sha256") -> bytes:
    """Transcript-Hash(messages) — the running handshake hash."""
    return hashlib.new(hash_name, messages).digest()


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = "sha256") -> bytes:
    """HKDF-Extract (RFC 5869) = HMAC(salt, ikm)."""
    if not salt:
        salt = b"\x00" * _digest_size(hash_name)
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """HKDF-Expand (RFC 5869)."""
    hash_len = _digest_size(hash_name)
    n = (length + hash_len - 1) // hash_len
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
    return bytes(okm[:length])


def hkdf_expand_label(
    secret: bytes, label: str, context: bytes, length: int, hash_name: str = "sha256"
) -> bytes:
    """HKDF-Expand-Label (RFC 8446 §7.1).

    HkdfLabel = uint16 length || opaque("tls13 " + label) || opaque(context).
    """
    full_label = b"tls13 " + label.encode("ascii")
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return hkdf_expand(secret, hkdf_label, length, hash_name)


def derive_secret(secret: bytes, label: str, transcript: bytes, hash_name: str = "sha256") -> bytes:
    """Derive-Secret(secret, label, transcript_hash) (RFC 8446 §7.1).

    `transcript` is the *already-computed* Transcript-Hash of the messages
    (or the empty-string hash for the "derived" step).
    """
    return hkdf_expand_label(secret, label, transcript, _digest_size(hash_name), hash_name)


@dataclass(slots=True)
class HandshakeKeys:
    """Derived handshake-phase secrets and the server/client AEAD key+iv."""

    hash_name: str
    key_len: int
    is_chacha: bool
    handshake_secret: bytes
    client_hs_secret: bytes
    server_hs_secret: bytes
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes


def handshake_traffic_keys(
    shared_secret: bytes, hello_transcript: bytes, cipher_suite: int
) -> HandshakeKeys:
    """Derive the TLS 1.3 handshake traffic keys.

    `hello_transcript` is the concatenation of the ClientHello and ServerHello
    *handshake messages* (no record headers). `cipher_suite` is the negotiated
    16-bit code (see CIPHER_SUITES).
    """
    hash_name, key_len, is_chacha = CIPHER_SUITES[cipher_suite]
    empty_hash = transcript_hash(b"", hash_name)
    th = transcript_hash(hello_transcript, hash_name)
    zeros = b"\x00" * _digest_size(hash_name)

    early_secret = hkdf_extract(b"", zeros, hash_name)
    derived = derive_secret(early_secret, "derived", empty_hash, hash_name)
    handshake_secret = hkdf_extract(derived, shared_secret, hash_name)

    client_hs = derive_secret(handshake_secret, "c hs traffic", th, hash_name)
    server_hs = derive_secret(handshake_secret, "s hs traffic", th, hash_name)

    return HandshakeKeys(
        hash_name=hash_name,
        key_len=key_len,
        is_chacha=is_chacha,
        handshake_secret=handshake_secret,
        client_hs_secret=client_hs,
        server_hs_secret=server_hs,
        client_key=hkdf_expand_label(client_hs, "key", b"", key_len, hash_name),
        client_iv=hkdf_expand_label(client_hs, "iv", b"", 12, hash_name),
        server_key=hkdf_expand_label(server_hs, "key", b"", key_len, hash_name),
        server_iv=hkdf_expand_label(server_hs, "iv", b"", 12, hash_name),
    )


def _record_nonce(iv: bytes, seq: int) -> bytes:
    """Per-record nonce = iv XOR seq (RFC 8446 §5.3)."""
    seq_bytes = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seq_bytes, strict=True))


def aead_open(key: bytes, iv: bytes, seq: int, record: bytes, *, is_chacha: bool) -> bytes | None:
    """AEAD-open one TLS 1.3 ciphertext record.

    `record` is a whole record *including* its 5-byte header (the header is the
    AEAD additional data). Returns the inner plaintext with the content-type
    byte and any zero padding stripped, or None on auth failure / short record.
    """
    if len(record) < 5:
        return None
    header = record[:5]
    ciphertext = record[5:]
    nonce = _record_nonce(iv, seq)
    aead: AESGCM | ChaCha20Poly1305 = ChaCha20Poly1305(key) if is_chacha else AESGCM(key)
    try:
        inner = aead.decrypt(nonce, ciphertext, header)
    except Exception:
        return None
    # Strip zero padding, then the trailing content-type byte.
    i = len(inner) - 1
    while i >= 0 and inner[i] == 0:
        i -= 1
    if i < 0:
        return None
    return inner[:i]  # drop the content-type byte at index i
