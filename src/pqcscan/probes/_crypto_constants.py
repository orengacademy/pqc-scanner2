"""Detect statically-linked / stripped crypto by its embedded constant tables.

DT_NEEDED / import-table linkage detection (see ``fs_binary_crypto``) misses
binaries that compile a crypto implementation *in* — statically-linked Go/Rust
binaries, stripped firmware, musl static builds — which link no ``libcrypto`` at
all. Many such implementations still embed the algorithm's well-known constant
tables (AES S-boxes, SHA/MD round constants, the ChaCha/Salsa "sigma" string,
the Keccak round constants). Each table is a byte sequence unique to one
algorithm, so a match is strong evidence the implementation is present.

A constant match proves *presence*, not *invocation* (the table could be dead
data), so matches are reported at **medium** confidence — below a resolved
``.dynsym`` "invoked" linkage but above an advertised-only signal.

Word-array constants are matched in **both** byte orders (a compiler stores
them in the target's endianness); byte-table constants (S-boxes) and the ASCII
sigma string are endian-independent. Needles are ≥16 bytes, so a coincidental
match on random data is ~2**-128 — effectively impossible.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _ConstSig:
    algorithm: str   # a name core.alg.classify() understands
    needle: bytes
    note: str


def _be(words: tuple[int, ...], size: int) -> bytes:
    return struct.pack(f">{len(words)}{'I' if size == 4 else 'Q'}", *words)


def _le(words: tuple[int, ...], size: int) -> bytes:
    return struct.pack(f"<{len(words)}{'I' if size == 4 else 'Q'}", *words)


# --- constant tables (canonical values) -----------------------------------

# AES forward / inverse S-box — first 32 bytes (the full 256-byte tables are
# endian-independent; 32 bytes is already uniquely identifying).
_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
_AES_INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb")

# SHA-256 round constants K[0..7] (32-bit).
_SHA256_K = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5)
# SHA-512 round constants K[0..2] (64-bit).
_SHA512_K = (0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f)
# SHA-1 round constants (the four 32-bit magic values).
_SHA1_K = (0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6)
# MD5 T[0..3] — floor(2**32 * abs(sin(i))).
_MD5_T = (0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee)
# Blowfish P-array init — the first digits of pi (also used by other pi-based
# designs, so labelled generically).
_BLOWFISH_P = (0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344)
# Keccak-f[1600] round constants RC[0..2] (64-bit) — SHA-3 / SHAKE, and thus
# the sponge underlying ML-KEM / ML-DSA / SLH-DSA.
_KECCAK_RC = (0x0000000000000001, 0x0000000000008082, 0x800000000000808a)


def _sigs() -> tuple[_ConstSig, ...]:
    out: list[_ConstSig] = [
        _ConstSig("AES", _AES_SBOX, "AES S-box"),
        _ConstSig("AES", _AES_INV_SBOX, "AES inverse S-box"),
        _ConstSig("SHA-256", _be(_SHA256_K, 4), "SHA-256 round constants (BE)"),
        _ConstSig("SHA-256", _le(_SHA256_K, 4), "SHA-256 round constants (LE)"),
        _ConstSig("SHA-512", _be(_SHA512_K, 8), "SHA-512 round constants (BE)"),
        _ConstSig("SHA-512", _le(_SHA512_K, 8), "SHA-512 round constants (LE)"),
        _ConstSig("SHA-1", _be(_SHA1_K, 4), "SHA-1 round constants (BE)"),
        _ConstSig("SHA-1", _le(_SHA1_K, 4), "SHA-1 round constants (LE)"),
        _ConstSig("MD5", _be(_MD5_T, 4), "MD5 T-table (BE)"),
        _ConstSig("MD5", _le(_MD5_T, 4), "MD5 T-table (LE)"),
        _ConstSig("Blowfish", _be(_BLOWFISH_P, 4), "Blowfish P-array / pi (BE)"),
        _ConstSig("Blowfish", _le(_BLOWFISH_P, 4), "Blowfish P-array / pi (LE)"),
        _ConstSig("ChaCha20", b"expand 32-byte k", "ChaCha20/Salsa20 sigma"),
        _ConstSig("ChaCha20", b"expand 16-byte k", "ChaCha20/Salsa20 tau"),
        _ConstSig("SHA-3", _be(_KECCAK_RC, 8), "Keccak round constants (BE)"),
        _ConstSig("SHA-3", _le(_KECCAK_RC, 8), "Keccak round constants (LE)"),
    ]
    return tuple(out)


_SIGNATURES = _sigs()


def scan_crypto_constants(data: bytes) -> list[tuple[str, str]]:
    """Return ``[(algorithm, note)]`` for each algorithm whose constant table is
    embedded in ``data``, at most one entry per algorithm (first signature that
    matches wins its note)."""
    found: dict[str, str] = {}
    for sig in _SIGNATURES:
        if sig.algorithm in found:
            continue
        if data.find(sig.needle) != -1:
            found[sig.algorithm] = sig.note
    return list(found.items())
