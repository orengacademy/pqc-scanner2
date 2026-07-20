"""Per-language, code-level migration snippets for weak → PQC-safe crypto.

`core.remediation` answers *what* to migrate to (the NIST target + FIPS
standard + deadline). This module answers *how*, at the source level: given a
classical algorithm and the language a finding came from, it returns a short
copy-pasteable before/after pair showing the concrete call to replace.

The mapping is keyed by (algorithm-family, language). A small classifier folds
the many algorithm spellings (``MD5``, ``SHA-1``, ``RSA-2048``, ``3DES`` …)
into a handful of families; each family carries per-language snippets plus a
language-agnostic ``generic`` fallback used for config/cert/network findings
that have no source language.

Guidance is deliberately conservative and standards-aligned:

* broken hashes (MD5/SHA-1) → SHA-256 (FIPS 180-4) — not a quantum issue, but
  they must go first;
* symmetric DES/3DES/RC4 → AES-256-GCM (FIPS 197) — double the key length for
  Grover headroom;
* RSA/ECDSA/DSA signatures → ML-DSA (FIPS 204), noting the migration is
  library-dependent today (OQS / BouncyCastle PQC / Go ``crypto/mlkem``);
* Diffie-Hellman / key establishment → hybrid ML-KEM (FIPS 203).
"""
from __future__ import annotations

# Algorithm-family classifier ------------------------------------------------
#
# Each entry maps a family key to the uppercased-name prefixes/tokens that
# select it. Order matters: the first family whose test passes wins, so more
# specific families (weak-hash, des, rc4) are checked before the broad
# asymmetric ones.


def _family(algorithm: str) -> str | None:
    """Fold an algorithm name into one migration family, or None if unknown."""
    a = algorithm.upper().replace("_", "-").strip()
    if not a or a == "N/A":
        return None

    # Broken hashes.
    if a.startswith(("MD5", "MD4", "MD2", "SHA-1", "SHA1")):
        return "weak-hash"

    # Symmetric — legacy block/stream ciphers.
    if a.startswith(("3DES", "TDES", "DES-EDE", "DES3", "TRIPLEDES")):
        return "des"
    if a.startswith("DES"):
        return "des"
    if a.startswith(("RC4", "ARCFOUR", "ARC4")):
        return "rc4"

    # Weak transport.
    if a.startswith(("TLS1.0", "TLSV1.0", "TLS-1.0", "TLSV1.1", "TLS1.1",
                     "TLS-1.1", "SSLV3", "SSL3", "SSLV2", "SSL2")):
        return "weak-tls"

    # Asymmetric signature / identity primitives.
    if a.startswith("RSA"):
        return "rsa"
    if a.startswith(("ECDSA", "ED25519", "ED448", "DSA", "SM2")):
        return "ecdsa"

    # Key establishment (Diffie-Hellman family, ECDH). Checked last so ECDSA
    # is not swallowed by an "EC" prefix.
    if a.startswith(("DH", "DHE", "ECDH", "ECDHE", "DIFFIE", "X25519", "X448",
                     "FFDHE")):
        return "dh"
    return None


# Snippet library ------------------------------------------------------------
#
# _SNIPPETS[family][language] = {"before", "after", "note"}. Every family also
# defines a "generic" language-agnostic entry used when no source language is
# known (cert / config / network findings). ``snippet_for`` falls back to the
# generic entry when a family lacks a language-specific snippet.

_Snippet = dict[str, str]

_SNIPPETS: dict[str, dict[str, _Snippet]] = {
    "weak-hash": {
        "python": {
            "before": "import hashlib\ndigest = hashlib.md5(data).hexdigest()",
            "after": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()",
            "note": "MD5/SHA-1 are collision-broken. Use SHA-256 (FIPS 180-4); "
                    "for password hashing use scrypt/argon2, not a bare hash.",
        },
        "java": {
            "before": 'MessageDigest md = MessageDigest.getInstance("MD5");',
            "after": 'MessageDigest md = MessageDigest.getInstance("SHA-256");',
            "note": "Replace MD5/SHA-1 with SHA-256. The provider ships it by "
                    "default; no extra dependency needed.",
        },
        "go": {
            "before": 'import "crypto/md5"\nh := md5.New()',
            "after": 'import "crypto/sha256"\nh := sha256.New()',
            "note": "Swap crypto/md5 or crypto/sha1 for crypto/sha256.",
        },
        "javascript": {
            "before": "const h = crypto.createHash('md5').update(data).digest('hex');",
            "after": "const h = crypto.createHash('sha256').update(data).digest('hex');",
            "note": "Use 'sha256' with Node's crypto, or crypto.subtle.digest("
                    "'SHA-256', ...) in the browser/WebCrypto.",
        },
        "generic": {
            "before": "digest = MD5(data)  // or SHA-1",
            "after": "digest = SHA-256(data)",
            "note": "Replace MD5/SHA-1 with SHA-256 (FIPS 180-4) everywhere it "
                    "is used for integrity or signatures.",
        },
    },
    "des": {
        "python": {
            "before": "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_CBC, iv)",
            "after": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                     "aes = AESGCM(key)  # 32-byte key\nct = aes.encrypt(nonce, data, aad)",
            "note": "DES/3DES are obsolete (64-bit block, small keys). Use "
                    "AES-256-GCM (FIPS 197) for authenticated encryption.",
        },
        "java": {
            "before": 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");',
            "after": 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");  // 256-bit key',
            "note": "Move DES/3DES to AES-256-GCM. Use a 12-byte random IV per "
                    "message and never reuse it under the same key.",
        },
        "go": {
            "before": 'import "crypto/des"\nblock, _ := des.NewCipher(key)',
            "after": 'import ("crypto/aes"; "crypto/cipher")\n'
                     "block, _ := aes.NewCipher(key)  // 32-byte key\n"
                     "gcm, _ := cipher.NewGCM(block)",
            "note": "Replace crypto/des with crypto/aes + cipher.NewGCM for "
                    "AES-256-GCM authenticated encryption.",
        },
        "javascript": {
            "before": "const c = crypto.createCipheriv('des-ede3-cbc', key, iv);",
            "after": "const c = crypto.createCipheriv('aes-256-gcm', key, iv);  // 32-byte key",
            "note": "Use 'aes-256-gcm' and read the auth tag via "
                    "cipher.getAuthTag() after finalising.",
        },
        "generic": {
            "before": "cipher = DES/3DES(key, ...)",
            "after": "cipher = AES-256-GCM(key, nonce, ...)",
            "note": "Retire DES/3DES; adopt AES-256-GCM (FIPS 197) with a unique "
                    "nonce per message.",
        },
    },
    "rc4": {
        "python": {
            "before": "# RC4 stream cipher (broken keystream biases)",
            "after": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                     "ct = AESGCM(key).encrypt(nonce, data, aad)  # or ChaCha20Poly1305",
            "note": "RC4 is prohibited. Use AES-256-GCM or ChaCha20-Poly1305 AEAD.",
        },
        "java": {
            "before": 'Cipher c = Cipher.getInstance("RC4");',
            "after": 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");  // 256-bit key',
            "note": "Replace RC4 with AES-256-GCM authenticated encryption.",
        },
        "go": {
            "before": 'import "crypto/rc4"\nc, _ := rc4.NewCipher(key)',
            "after": 'import ("crypto/aes"; "crypto/cipher")\n'
                     "block, _ := aes.NewCipher(key)\ngcm, _ := cipher.NewGCM(block)",
            "note": "crypto/rc4 is deprecated. Use AES-256-GCM, or "
                    "golang.org/x/crypto/chacha20poly1305.",
        },
        "javascript": {
            "before": "const c = crypto.createCipheriv('rc4', key, '');",
            "after": "const c = crypto.createCipheriv('aes-256-gcm', key, iv);  // 32-byte key",
            "note": "Use 'aes-256-gcm' (or 'chacha20-poly1305') instead of RC4.",
        },
        "generic": {
            "before": "cipher = RC4(key)",
            "after": "cipher = AES-256-GCM(key, nonce, ...)",
            "note": "RC4 is broken. Move to AES-256-GCM or ChaCha20-Poly1305.",
        },
    },
    "rsa": {
        "python": {
            "before": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                      "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            "after": "# Interim: raise to RSA-3072+; target: ML-DSA-65 (FIPS 204).\n"
                     "# ML-DSA is not yet in `cryptography`; use an OQS provider today, e.g.\n"
                     "#   import oqs; sig = oqs.Signature('ML-DSA-65')\n"
                     "# and deploy hybrid (ML-DSA + ECDSA) during transition.",
            "note": "RSA signatures/keys are quantum-vulnerable. Migrate signing "
                    "to ML-DSA-65 (FIPS 204); for key establishment see the DH "
                    "family (ML-KEM, FIPS 203). Deploy hybrid during transition.",
        },
        "java": {
            "before": 'KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n'
                      "g.initialize(2048);",
            "after": '// BouncyCastle PQC provider (bcpqc):\n'
                     'KeyPairGenerator g = KeyPairGenerator.getInstance(\n'
                     '        "ML-DSA", "BCPQC");  // signatures, FIPS 204\n'
                     '// Key establishment -> "ML-KEM" (FIPS 203); deploy hybrid.',
            "note": "Register org.bouncycastle.pqc.jcajce.provider and generate "
                    "ML-DSA (sign) / ML-KEM (KEM) keys. Run hybrid with the "
                    "existing RSA/ECDSA key during transition.",
        },
        "go": {
            "before": 'import "crypto/rsa"\n'
                      "key, _ := rsa.GenerateKey(rand.Reader, 2048)",
            "after": "// Signatures -> ML-DSA-65 (FIPS 204) via a PQC library today\n"
                     "// (e.g. cloudflare/circl sign/mldsa). Key establishment ->\n"
                     '// crypto/mlkem (Go 1.24+): mlkem.GenerateKey768(). Hybrid.',
            "note": "Move RSA signing to ML-DSA-65 (FIPS 204). For KEMs, Go "
                    "1.24+ ships crypto/mlkem; deploy hybrid ML-KEM + X25519.",
        },
        "javascript": {
            "before": "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });",
            "after": "// Node WebCrypto has no ML-DSA/ML-KEM yet. Use an OQS-based\n"
                     "// binding (e.g. liboqs-node) for ML-DSA-65 signatures and\n"
                     "// ML-KEM-768 key establishment; deploy hybrid during rollout.",
            "note": "RSA is quantum-vulnerable. Adopt ML-DSA-65 (FIPS 204) for "
                    "signing and ML-KEM-768 (FIPS 203) for key establishment via "
                    "a PQC library; run hybrid during transition.",
        },
        "generic": {
            "before": "certificate/key signed with RSA-2048",
            "after": "reissue with ML-DSA-65 (FIPS 204), or a hybrid "
                     "ML-DSA-65 + ECDSA-P256 certificate during transition",
            "note": "Plan reissuance to an ML-DSA (or hybrid) certificate; for "
                    "TLS key exchange enable a hybrid ML-KEM group (X25519MLKEM768).",
        },
    },
    "ecdsa": {
        "python": {
            "before": "from cryptography.hazmat.primitives.asymmetric import ec\n"
                      "key = ec.generate_private_key(ec.SECP256R1())",
            "after": "# Target: ML-DSA-65 (FIPS 204). Not yet in `cryptography`;\n"
                     "# use an OQS provider today:\n"
                     "#   import oqs; sig = oqs.Signature('ML-DSA-65')\n"
                     "# and deploy hybrid (ML-DSA + ECDSA) during transition.",
            "note": "ECDSA/EdDSA are quantum-vulnerable. Migrate signing to "
                    "ML-DSA-65 (FIPS 204); deploy hybrid during transition.",
        },
        "java": {
            "before": 'KeyPairGenerator g = KeyPairGenerator.getInstance("EC");\n'
                      'g.initialize(new ECGenParameterSpec("secp256r1"));',
            "after": '// BouncyCastle PQC provider (bcpqc):\n'
                     'KeyPairGenerator g = KeyPairGenerator.getInstance(\n'
                     '        "ML-DSA", "BCPQC");  // signatures, FIPS 204',
            "note": "Register the BouncyCastle PQC provider and generate ML-DSA "
                    "keys. Run hybrid with the existing ECDSA key during rollout.",
        },
        "go": {
            "before": 'import "crypto/ecdsa"\n'
                      "key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)",
            "after": "// Move signing to ML-DSA-65 (FIPS 204) via a PQC library\n"
                     "// today (e.g. cloudflare/circl sign/mldsa); deploy hybrid\n"
                     "// ML-DSA + ECDSA during transition.",
            "note": "ECDSA is quantum-vulnerable. Migrate signing to ML-DSA-65 "
                    "(FIPS 204); deploy hybrid during transition.",
        },
        "javascript": {
            "before": "crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });",
            "after": "// WebCrypto has no ML-DSA yet. Use an OQS-based binding\n"
                     "// (e.g. liboqs-node) for ML-DSA-65 signatures; run hybrid\n"
                     "// (ML-DSA + ECDSA) during transition.",
            "note": "Adopt ML-DSA-65 (FIPS 204) for signing via a PQC library; "
                    "deploy hybrid during transition.",
        },
        "generic": {
            "before": "certificate/key signed with ECDSA-P256",
            "after": "reissue with ML-DSA-65 (FIPS 204), or a hybrid "
                     "ML-DSA-65 + ECDSA-P256 certificate during transition",
            "note": "Plan reissuance to an ML-DSA (or hybrid) certificate; enable "
                    "a hybrid ML-KEM group (X25519MLKEM768) for TLS key exchange.",
        },
    },
    "dh": {
        "python": {
            "before": "from cryptography.hazmat.primitives.asymmetric import dh\n"
                      "params = dh.generate_parameters(generator=2, key_size=2048)",
            "after": "# Key establishment target: ML-KEM-768 (FIPS 203), deployed\n"
                     "# hybrid as X25519MLKEM768. Use an OQS provider today:\n"
                     "#   import oqs; kem = oqs.KeyEncapsulation('ML-KEM-768')",
            "note": "Classical (EC)DH is harvest-now-decrypt-later exposed. "
                    "Migrate key establishment to hybrid ML-KEM-768 first.",
        },
        "go": {
            "before": "// (EC)DH key agreement, e.g. crypto/ecdh P256",
            "after": '// Go 1.24+: import "crypto/mlkem"\n'
                     "dk, _ := mlkem.GenerateKey768()  // deploy hybrid X25519MLKEM768",
            "note": "Go 1.24+ ships crypto/mlkem. Prefer the hybrid "
                    "X25519MLKEM768 group; migrate key establishment first (HNDL).",
        },
        "generic": {
            "before": "key exchange using classical (EC)DH",
            "after": "enable hybrid ML-KEM key establishment (X25519MLKEM768, "
                     "FIPS 203) and prefer it in the negotiated group list",
            "note": "Diffie-Hellman is harvest-now-decrypt-later exposed. Move "
                    "key establishment to hybrid ML-KEM-768 as the first step.",
        },
    },
    "weak-tls": {
        "generic": {
            "before": "protocols: TLSv1.0, TLSv1.1  (or SSLv2/SSLv3)",
            "after": "protocols: TLSv1.2, TLSv1.3\ngroups: X25519MLKEM768:X25519:P-256",
            "note": "Disable SSLv2/SSLv3/TLS 1.0/1.1. Require TLS 1.2+ (prefer "
                    "1.3) and offer the hybrid X25519MLKEM768 group for PQC key "
                    "establishment.",
        },
    },
}


def snippet_for(algorithm: str, language: str | None) -> dict[str, str] | None:
    """Return a copy-pasteable before/after migration snippet.

    Parameters
    ----------
    algorithm:
        The classical algorithm name as recorded on a finding (any common
        spelling, e.g. ``"MD5"``, ``"RSA-2048"``, ``"3DES-CBC"``).
    language:
        The source language inferred from the finding's probe id
        (``"python"`` / ``"java"`` / ``"go"`` / ``"javascript"``), or ``None``
        for language-agnostic (config/cert/network) findings.

    Returns a ``{"language", "before", "after", "note"}`` dict, or ``None``
    when the algorithm maps to no known migration family.
    """
    family = _family(algorithm)
    if family is None:
        return None
    lang_table = _SNIPPETS[family]

    lang = language.lower() if language else None
    entry = lang_table.get(lang) if lang else None
    resolved_lang = lang
    if entry is None:
        entry = lang_table.get("generic")
        resolved_lang = "generic"
    if entry is None:
        return None

    return {
        "language": resolved_lang or "generic",
        "before": entry["before"],
        "after": entry["after"],
        "note": entry["note"],
    }
