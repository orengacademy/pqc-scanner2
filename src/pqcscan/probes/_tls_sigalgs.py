"""signature_algorithms offered by the raw-socket TLS probes (one list for all).

Without ed25519/ed448 and ML-DSA a server whose only certificate is EdDSA or
ML-DSA aborts the handshake — which read as "TLS 1.3 not supported" or "no key
exchange seen" on exactly the most modern servers.
"""
from __future__ import annotations

SIG_ALGS: tuple[int, ...] = (
    0x0403, 0x0503, 0x0603,          # ecdsa_secp{256,384,521}
    0x0804, 0x0805, 0x0806,          # rsa_pss_rsae_sha{256,384,512}
    0x0809, 0x080A, 0x080B,          # rsa_pss_pss_sha{256,384,512}
    0x0401, 0x0501, 0x0601,          # rsa_pkcs1_sha{256,384,512}
    0x0807, 0x0808,                  # ed25519, ed448
    0x0904, 0x0905, 0x0906,          # mldsa44, mldsa65, mldsa87
)
