"""One canonical name for a `cryptography` key object (public or private).

Shared by every cert / key probe so RSA-2048, ECDSA-secp256r1, DSA-1024,
Ed25519, Ed448 spell the same everywhere `core.alg.classify` sees them.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa


def key_algorithm(key: object) -> str:
    if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        return f"ECDSA-{key.curve.name}"
    if isinstance(key, dsa.DSAPublicKey | dsa.DSAPrivateKey):
        return f"DSA-{key.key_size}"
    if isinstance(key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey | ed448.Ed448PrivateKey):
        return "Ed448"
    return type(key).__name__
