"""Fixture generator for the accuracy benchmark corpus.

Writes source/config fixtures, certs, keys, keystores, SQLite DBs, TLS endpoint
specs and OCI image layouts into benchmark/corpus/cases/, then rewrites
benchmark/corpus/CORPUS.sha256 (sha256sum-format listing of every corpus file;
the corpus hash is the sha256 of that listing).

    PYTHONPATH=src python benchmark/corpus/generate_fixtures.py          # regenerate + hash
    PYTHONPATH=src python benchmark/corpus/generate_fixtures.py --hash   # hash only

Determinism: every key is derived from a fixed seed (RSA primes from a seeded
PRNG, EC/Ed25519/ML-DSA from seed bytes), serials and dates are fixed, ECDSA
signs per RFC 6979, and tar/JSON output is canonical. Formats whose writer
always salts or randomises (ML-DSA signatures, PKCS#12, encrypted PKCS#8 and
PEM) are written once and kept (``keep=True``); CORPUS.sha256 pins those bytes.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import math
import random
import sqlite3
import sys
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    pkcs12,
)

CORPUS = Path(__file__).resolve().parent
CASES = CORPUS / "cases"
sys.path.insert(0, str(CORPUS.parent))
import run_benchmark  # noqa: E402  (corpus_listing lives with the harness)


def w(rel: str, text: str) -> None:
    p = CASES / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text if text.endswith("\n") else text + "\n")


def wb(rel: str, data: bytes, *, keep: bool = False) -> None:
    """Write bytes; with keep=True an existing file is left alone (randomised format)."""
    p = CASES / rel
    if keep and p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def text_fixtures() -> None:
    # NOTE: source-code probes walk a directory tree (rglob); a bare-file root
    # scans nothing. So every code case is its own directory holding one source
    # file, and the manifest input points at that directory.

    # ---------------------------------------------------------------- Python (AST)
    w("py-md5-real/src.py", 'import hashlib\n\ndigest = hashlib.md5(b"x").hexdigest()\n')
    w("py-sha1-alias/src.py", 'import hashlib as h\n\ndigest = h.sha1(b"x").hexdigest()\n')
    w("py-rsa2048/src.py",
      "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
      "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    w("py-des-real/src.py",
      "from Crypto.Cipher import DES\n\n"
      'cipher = DES.new(b"8bytekey", DES.MODE_ECB)\n')
    w("py-ec-real/src.py",
      "from cryptography.hazmat.primitives.asymmetric import ec\n\n"
      "key = ec.generate_private_key(ec.SECP256R1())\n")
    w("py-comment-md5/src.py", "x = 1  # hashlib.md5() is legacy, do not use\n")
    w("py-string-md5/src.py", 'label = "use hashlib.md5 for the checksum"\n')
    w("py-clean-sha256/src.py", 'import hashlib\n\ndigest = hashlib.sha256(b"x").hexdigest()\n')

    # ------------------------------------------------------------------------- Go
    w("go-md5-real/main.go",
      'package main\n\nimport "crypto/md5"\n\nfunc f() []byte {\n'
      '\th := md5.New()\n\treturn h.Sum(nil)\n}\n')
    w("go-comment-md5/main.go",
      'package main\n\nfunc f() {\n\t// md5.New() must never be used here\n}\n')
    w("go-string-md5/main.go",
      'package main\n\nfunc f() string {\n\treturn "md5.New() disabled"\n}\n')
    w("go-clean-sha256/main.go",
      'package main\n\nimport "crypto/sha256"\n\nfunc f() []byte {\n'
      '\th := sha256.New()\n\treturn h.Sum(nil)\n}\n')

    # ----------------------------------------------------------------------- Java
    w("java-md5-real/A.java",
      "import java.security.MessageDigest;\n\nclass A {\n"
      '  void f() throws Exception {\n'
      '    MessageDigest md = MessageDigest.getInstance("MD5");\n  }\n}\n')
    w("java-des-real/B.java",
      "import javax.crypto.Cipher;\n\nclass B {\n"
      '  void f() throws Exception {\n'
      '    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");\n  }\n}\n')
    w("java-comment-md5/C.java",
      "class C {\n  void f() {\n"
      '    // MessageDigest.getInstance("MD5") is banned\n  }\n}\n')
    w("java-string-md5/D.java",
      "class D {\n  void f() {\n"
      "    String m = \"never call MessageDigest.getInstance('MD5')\";\n  }\n}\n")

    # ------------------------------------------------------------------ JavaScript
    w("js-md5-real/app.js",
      "const crypto = require('crypto');\n\n"
      "const h = crypto.createHash('md5');\n")
    w("js-comment-md5/app.js",
      "function f() {\n  // crypto.createHash('md5') is forbidden\n}\n")
    w("js-string-md5/app.js",
      'const note = "crypto.createHash(\'md5\') is forbidden";\n')
    w("js-clean-sha256/app.js",
      "const crypto = require('crypto');\n\n"
      "const h = crypto.createHash('sha256');\n")

    # ------------------------------------------------------------------------ PHP
    w("php-md5-real/index.php", "<?php\n$hash = md5($password);\n")
    w("php-comment-md5/index.php", "<?php\n// md5($password) is forbidden\n$x = 1;\n")
    w("php-string-md5/index.php", '<?php\n$note = "md5($password) is forbidden";\n')

    # ----------------------------------------------------------------------- Rust
    w("rust-md5-real/lib.rs", "use md5;\n\nfn f() {\n    let _d = md5::compute(b\"x\");\n}\n")
    w("rust-comment-md5/lib.rs", "fn f() {\n    // use md5; is forbidden\n}\n")
    w("rust-string-md5/lib.rs", 'fn f() {\n    let _s = "use md5; is forbidden";\n}\n')

    # ------------------------------------------------------------------------- F5
    w("f5-weak.conf",
      "ltm profile client-ssl /Common/weak {\n"
      "    options { no-tlsv1.3 }\n}\n")
    w("f5-hardened.conf",
      "ltm profile client-ssl /Common/hardened {\n"
      "    options { dont-insert-empty-fragments }\n"
      "    ciphers DEFAULT\n}\n")

    # ------------------------------------------------------------------ NetScaler
    w("netscaler-weak.conf", "set ssl vserver vs1 -tls1 ENABLED\n")
    w("netscaler-cipher-weak.conf", "bind ssl vserver vs1 -cipherName RC4-MD5\n")
    w("netscaler-hardened.conf",
      "set ssl vserver vs1 -ssl3 DISABLED -tls1 DISABLED "
      "-tls11 DISABLED -tls12 ENABLED -tls13 ENABLED\n")

    # ---------------------------------------------------------------------- nginx
    w("nginx-weak.conf",
      "server {\n    ssl_protocols TLSv1 TLSv1.1;\n}\n")
    w("nginx-hardened.conf",
      "server {\n    ssl_protocols TLSv1.2 TLSv1.3;\n"
      "    ssl_ciphers HIGH:!aNULL:!eNULL;\n}\n")

    # -------------------------------------------------------------------- haproxy
    w("haproxy-weak.cfg",
      "frontend fe\n    bind :443 ssl crt /etc/x.pem\n"
      "    ssl-default-bind-options ssl-min-ver TLSv1.0\n")
    w("haproxy-hardened.cfg",
      "frontend fe\n    bind :443 ssl crt /etc/x.pem\n"
      "    ssl-default-bind-options ssl-min-ver TLSv1.2\n"
      "    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384\n")

    # ----------------------------------------------------------------------- sshd
    w("sshd-weak.conf", "KexAlgorithms diffie-hellman-group1-sha1\n")
    w("sshd-hardened.conf",
      "Ciphers aes256-gcm@openssh.com\nKexAlgorithms curve25519-sha256\n")



# ------------------------------------------------------------ seeded key material
_SMALL_PRIMES = [p for p in range(3, 4000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _is_probable_prime(n: int, rnd: random.Random) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(40):
        x = pow(rnd.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def seeded_rsa(bits: int, seed: str) -> rsa.RSAPrivateKey:
    """RSA key from a seeded PRNG — `cryptography` cannot seed its own keygen."""
    rnd = random.Random(seed)
    e = 65537

    def prime() -> int:
        while True:
            c = rnd.getrandbits(bits // 2) | (3 << (bits // 2 - 2)) | 1  # top two bits -> n has `bits` bits
            if math.gcd(c - 1, e) == 1 and _is_probable_prime(c, rnd):
                return c

    p, q = prime(), prime()
    d = pow(e, -1, (p - 1) * (q - 1))
    return rsa.RSAPrivateNumbers(
        p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q),
        rsa.RSAPublicNumbers(e, p * q),
    ).private_key()


def _seed(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def seeded_ec(curve: ec.EllipticCurve, seed: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(_seed(seed), "big") >> 8, curve)


def seeded_ed25519(seed: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(_seed(seed))


def seeded_mldsa65(seed: str) -> mldsa.MLDSA65PrivateKey:
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(_seed(seed))


_NOT_BEFORE = datetime.datetime(2024, 1, 1)


def make_cert(key, cn: str, *, issuer_key=None) -> x509.Certificate:  # type: ignore[no-untyped-def]
    """Self-signed (or issuer-signed) cert with fixed serial/dates."""
    signer = issuer_key or key
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(_seed(cn)[:8], "big"))
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + datetime.timedelta(days=36500))
    )
    if isinstance(signer, ed25519.Ed25519PrivateKey | mldsa.MLDSA65PrivateKey):
        return builder.sign(signer, None)
    if isinstance(signer, ec.EllipticCurvePrivateKey):
        return builder.sign(signer, hashes.SHA256(), ecdsa_deterministic=True)
    return builder.sign(signer, hashes.SHA256())


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.PEM)


def pkcs8(key, password: bytes | None = None) -> bytes:  # type: ignore[no-untyped-def]
    enc = BestAvailableEncryption(password) if password else NoEncryption()
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)


# ------------------------------------------------------------------- certs
def cert_fixtures() -> None:
    rsa1024 = seeded_rsa(1024, "cert-rsa1024")
    wb("cert-rsa1024/server.pem", pem(make_cert(rsa1024, "weak-rsa1024.example")))
    # ML-DSA signatures are hedged (randomised) — written once, then pinned by CORPUS.sha256.
    mld = seeded_mldsa65("cert-mldsa65")
    wb("cert-mldsa65/server.pem", pem(make_cert(mld, "pqc-mldsa65.example")), keep=True)
    der = make_cert(mld, "pqc-mldsa65-der.example").public_bytes(Encoding.DER)
    wb("cert-mldsa65-der/server.der", der, keep=True)

    specs = [  # (case, key, encoding)
        ("cert-rsa2048-pem", seeded_rsa(2048, "cert-rsa2048"), "pem"),
        ("cert-rsa2048-der", seeded_rsa(2048, "cert-rsa2048-der"), "der"),
        ("cert-rsa3072-pem", seeded_rsa(3072, "cert-rsa3072"), "pem"),
        ("cert-rsa4096-der", seeded_rsa(4096, "cert-rsa4096"), "der"),
        ("cert-ecdsa-p256-pem", seeded_ec(ec.SECP256R1(), "cert-p256"), "pem"),
        ("cert-ecdsa-p384-der", seeded_ec(ec.SECP384R1(), "cert-p384"), "der"),
        ("cert-ed25519-pem", seeded_ed25519("cert-ed25519"), "pem"),
        ("cert-ed25519-der", seeded_ed25519("cert-ed25519-der"), "der"),
    ]
    for case, key, enc in specs:
        cert = make_cert(key, f"{case}.example")
        if enc == "pem":
            wb(f"{case}/server.crt", pem(cert))
        else:
            wb(f"{case}/server.der", cert.public_bytes(Encoding.DER))

    # PKCS#12 keystores (fs.keystore.pkcs12). Salted by the writer -> keep=True.
    r2048 = seeded_rsa(2048, "p12-rsa2048")
    wb("p12-rsa2048-changeit/keystore.p12", pkcs12.serialize_key_and_certificates(
        b"server", r2048, make_cert(r2048, "p12-rsa2048.example"), None,
        BestAvailableEncryption(b"changeit")), keep=True)
    ed = seeded_ed25519("p12-ed25519")
    wb("p12-ed25519-nopass/keystore.p12", pkcs12.serialize_key_and_certificates(
        b"server", ed, make_cert(ed, "p12-ed25519.example"), None, NoEncryption()), keep=True)
    p256 = seeded_ec(ec.SECP256R1(), "p12-p256")
    wb("p12-ecdsa-p256-test/keystore.pfx", pkcs12.serialize_key_and_certificates(
        b"server", p256, make_cert(p256, "p12-p256.example"), None,
        BestAvailableEncryption(b"test")), keep=True)
    ca = seeded_rsa(2048, "p12-truststore-rsa")
    wb("p12-truststore-rsa2048/truststore.p12", pkcs12.serialize_key_and_certificates(
        b"truststore", None, None, [make_cert(ca, "truststore-rsa-ca.example")],
        BestAvailableEncryption(b"changeit")), keep=True)
    # A CA cert whose SPKI names an unknown key type: it loads, but public_key()
    # raises. Next to it, a second keystore that must still be scanned.
    garbage = seeded_ed25519("p12-garbage-ca")
    der = make_cert(garbage, "garbage-ca.example").public_bytes(Encoding.DER)
    spki = b"\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"   # AlgorithmIdentifier(Ed25519) + BIT STRING
    garbage_ca = x509.load_der_x509_certificate(der.replace(spki, spki[:6] + b"\x7f" + spki[7:]))
    weak = seeded_rsa(1024, "p12-weak-leaf")
    wb("p12-weak-plus-garbage-ca/weak.p12", pkcs12.serialize_key_and_certificates(
        b"weak", weak, make_cert(weak, "p12-weak.example"), [garbage_ca], NoEncryption()), keep=True)
    other = seeded_ed25519("p12-sibling")
    wb("p12-weak-plus-garbage-ca/other.p12", pkcs12.serialize_key_and_certificates(
        b"other", other, make_cert(other, "p12-sibling.example"), None, NoEncryption()), keep=True)
    wb("p12-truststore-mldsa65/truststore.p12", pkcs12.serialize_key_and_certificates(
        b"truststore", None, None, [make_cert(seeded_mldsa65("p12-ts-mldsa"), "truststore-mldsa.example")],
        BestAvailableEncryption(b"changeit")), keep=True)


# -------------------------------------------------------------------- keys
def key_fixtures() -> None:
    wb("key-rsa2048-pkcs8/server.key", pkcs8(seeded_rsa(2048, "key-rsa2048")))
    wb("key-rsa1024-traditional/server.key", seeded_rsa(1024, "key-rsa1024").private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    wb("key-ecdsa-p384-pkcs8/server.pem", pkcs8(seeded_ec(ec.SECP384R1(), "key-p384")))
    wb("key-ed25519-pkcs8/server.pem", pkcs8(seeded_ed25519("key-ed25519")))
    wb("key-mldsa65-pkcs8/server.pem", pkcs8(seeded_mldsa65("key-mldsa65")))
    # Encrypted at rest (fs.cert.privkey_encrypted). Random salt/IV -> keep=True.
    wb("key-rsa2048-pkcs8-encrypted/server.key", pkcs8(seeded_rsa(2048, "key-enc"), b"test"), keep=True)
    wb("key-rsa2048-legacy-encrypted/server.pem", seeded_rsa(2048, "key-legacy").private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, BestAvailableEncryption(b"test")), keep=True)

    # OpenSSH host-key layout (fs.ssh.host_keys reads the *.pub / authorized_keys files).
    def ssh_pair(case: str, name: str, key) -> None:  # type: ignore[no-untyped-def]
        wb(f"{case}/{name}", key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()), keep=True)
        pub = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        wb(f"{case}/{name}.pub", pub + f" root@{case}\n".encode())

    ssh_pair("ssh-hostkey-rsa1024", "ssh_host_rsa_key", seeded_rsa(1024, "ssh-rsa1024"))
    ssh_pair("ssh-hostkey-ed25519", "ssh_host_ed25519_key", seeded_ed25519("ssh-ed25519"))
    ssh_pair("ssh-hostkey-ecdsa-p256", "ssh_host_ecdsa_key", seeded_ec(ec.SECP256R1(), "ssh-p256"))
    user = seeded_rsa(2048, "ssh-authorized-rsa2048").public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    w("ssh-authorized-keys-rsa2048/authorized_keys",
      'from="10.0.0.0/8",no-agent-forwarding ' + user.decode() + " deploy@ci")
    w("ssh-authorized-keys-comments/authorized_keys",
      "# managed by config-mgmt; no keys provisioned on this host\n#\n# ssh-rsa keys are not accepted here\n")


# ------------------------------------------------------- source (C#, Rust, Kotlin)
def more_source_fixtures() -> None:
    w("cs-md5-real/Hash.cs",
      "using System.Security.Cryptography;\n\nclass Hash {\n"
      "    byte[] F(byte[] d) { using var h = MD5.Create(); return h.ComputeHash(d); }\n}\n")
    w("cs-rsa-real/Keys.cs",
      "using System.Security.Cryptography;\n\nclass Keys {\n"
      "    RSA F() { return RSA.Create(2048); }\n}\n")
    w("cs-des-real/Legacy.cs",
      "using System.Security.Cryptography;\n\nclass Legacy {\n"
      "    SymmetricAlgorithm F() { return new TripleDESCryptoServiceProvider(); }\n}\n")
    w("cs-comment-md5/Hash.cs",
      "class Hash {\n    // MD5.Create() is banned by policy\n    int F() { return 1; }\n}\n")
    w("cs-string-md5/Hash.cs",
      'class Hash {\n    string F() { return "never call MD5.Create() here"; }\n}\n')
    w("cs-verbatim-md5/Hash.cs",
      'class Hash {\n    string F() { return @"legacy: MD5.Create() and RSA.Create(1024)"; }\n}\n')
    w("cs-clean-sha256/Hash.cs",
      "using System.Security.Cryptography;\n\nclass Hash {\n"
      "    byte[] F(byte[] d) { using var h = SHA256.Create(); return h.ComputeHash(d); }\n}\n")

    w("rust-rsa-real/lib.rs",
      "use rsa::RsaPrivateKey;\n\nfn f(rng: &mut impl rand::CryptoRng) {\n"
      "    let _k = RsaPrivateKey::new(rng, 2048).unwrap();\n}\n")
    w("rust-des-real/lib.rs",
      "use des::Des;\nuse cipher::KeyInit;\n\nfn f(k: &[u8; 8]) {\n    let _c = Des::new(k.into());\n}\n")
    w("rust-raw-string-md5/lib.rs",
      'fn f() -> &\'static str {\n    r#"use md5; let _ = md5::compute(b"x");"#\n}\n')
    w("rust-clean-sha256/lib.rs",
      "use sha2::{Digest, Sha256};\n\nfn f() {\n    let _d = Sha256::digest(b\"x\");\n}\n")

    w("kt-md5-real/Hash.kt",
      "import java.security.MessageDigest\n\nfun f(): ByteArray =\n"
      '    MessageDigest.getInstance("MD5").digest("x".toByteArray())\n')
    w("kt-rsa-real/Keys.kt",
      "import java.security.KeyPairGenerator\n\nfun f() {\n"
      '    val g = KeyPairGenerator.getInstance("RSA")\n    g.initialize(2048)\n}\n')
    w("kt-comment-md5/Hash.kt",
      'fun f() {\n    // MessageDigest.getInstance("MD5") is banned\n}\n')
    w("kt-string-md5/Hash.kt",
      "fun f() = \"never call MessageDigest.getInstance('MD5')\"\n")
    w("kt-raw-string-md5/Hash.kt",
      'fun f() = """\n    MessageDigest.getInstance("MD5")\n"""\n')
    # Stripper evasion attempts (security review of the text-block rule): a crafted
    # string must not make the stripper blank the real call after it.
    w("java-textblock-evasion/E.java",
      "import java.security.MessageDigest;\n\nclass E {\n"
      '    String a = """\n        escaped \\""" still inside\n        """;\n'
      '    void f() throws Exception { MessageDigest.getInstance("MD5"); }\n'
      '    String b = """\n        tail\n        """;\n}\n')
    w("java-textblock-md5-string/S.java",
      'class S {\n    String doc = """\n        call MessageDigest.getInstance("MD5") here\n        """;\n}\n')
    w("kt-rawstring-evasion/E.kt",
      "import java.security.MessageDigest\n\n"
      'fun f(b: ByteArray): String = """prefix"""" + MessageDigest.getInstance("MD5").digest(b).size\n')
    w("kt-rawstring-trailing-quote-md5/S.kt",
      'val s = """MessageDigest.getInstance("MD5")""""\n')
    # code.crypto_primitives also scans .ts/.rb/.c/.cpp/.swift: real use vs the
    # token only in a comment or in a prose string.
    for lang, fname, real, comment, string in (
        ("ts", "app.ts", 'import { createHash } from "crypto";\nconst h = createHash("md5");\n',
         '// createHash("md5") is banned\nexport const x = 1;\n', 'export const note = "never use md5 here";\n'),
        ("rb", "hash.rb", 'require "digest"\nd = Digest::MD5.hexdigest(data)\n',
         "# Digest::MD5 is banned\nx = 1\n", 'note = "never use md5 here"\n'),
        ("c", "hash.c", "#include <openssl/md5.h>\n"
         "void f(const unsigned char *d, size_t n, unsigned char *o) { MD5(d, n, o); }\n",
         "/* MD5() is banned */\nint x;\n", 'const char *note = "never use md5 here";\n'),
        ("cpp", "hash.cpp", "#include <openssl/md5.h>\n"
         "void f(const unsigned char* d, size_t n, unsigned char* o) { MD5(d, n, o); }\n",
         "// MD5() is banned\nint x = 1;\n", 'const char* note = "never use md5 here";\n'),
        ("swift", "Hash.swift", "import CryptoKit\nlet d = Insecure.MD5.hash(data: data)\n",
         "// Insecure.MD5 is banned\nlet x = 1\n", 'let note = "never use md5 here"\n'),
    ):
        w(f"{lang}-md5-real/{fname}", real)
        w(f"{lang}-comment-md5/{fname}", comment)
        w(f"{lang}-string-md5/{fname}", string)
    # Evasion attempts against code.crypto_primitives (security review): code
    # inside an interpolated literal, and literals the lexers must not trust.
    w("js-template-md5/app.js", "const s = `digest ${md5(x)}`;\n")
    w("py-fstring-md5/src.py", 'import hashlib\n\ns = f"digest {hashlib.md5(b\'x\').hexdigest()}"\n')
    # Ruby ?" is a one-char literal and Swift #"a"b"# a raw string holding a quote;
    # a Java-style lexer would pair the stray quote with a later one and blank the
    # real call between them.
    w("rb-charliteral-then-md5/hash.rb",
      'q = ?"; d = Digest::MD5.hexdigest(x); r = "done"\n')
    w("swift-rawstring-then-md5/Hash.swift",
      'let s = #"a"b"#; let d = Insecure.MD5.hash(data: x); let e = "done"\n')
    # Crafted-literal evasions (security review): one construct the lexer misreads
    # (regex literal, nested f-string quote, C# 11 raw string, nested template)
    # leaves a stray quote that opens a "string" swallowing the real call.
    w("js-regex-quote-md5/app.js",
      "const r = /\"/; const h = crypto.createHash('md5'); const s = \"y\";\n")
    w("ts-regex-quote-md5/app.ts",
      "const r = /'/; const h = crypto.createHash(\"md5\"); const s = 'y';\n")
    w("py312-fstring-quote-md5/src.py",
      "import hashlib\n\nb = b\"x\"\ns = f\"{'\"'}\"; h = hashlib.md5(b).hexdigest(); t = 'x'  # noqa: E702\n")
    w("py312-fstring-quote-md5/ruff.toml",
      "# This fixture uses Python 3.12 f-string syntax (a quote reused inside {...}) on purpose.\n"
      "extend = \"../../../../pyproject.toml\"\ntarget-version = \"py312\"\ncache-dir = \"../../../../.ruff_cache\"\n")
    w("cs-rawstring-quote-md5/Hash.cs",
      "class H {\n    void F() { var a = \"\"\"a\\\"\"\"; var h = MD5.Create(); var s = \"x\"; }\n}\n")
    w("kt-template-quote-md5/Hash.kt",
      "val a = \"${\"\\\"\"}\"; val d = MessageDigest.getInstance(md5); val s = \"y\"\n")
    w("kt-clean-sha256/Hash.kt",
      "import java.security.MessageDigest\n\nfun f(): ByteArray =\n"
      '    MessageDigest.getInstance("SHA-256").digest("x".toByteArray())\n')


# ---------------------------------------------------------------- TLS endpoints
# Each endpoint case is a directory with endpoint.yaml + server.crt/server.key.
# run_benchmark starts a 127.0.0.1 TLS server from the spec for the case.
def endpoint_fixtures() -> None:
    def endpoint(case: str, key, spec: dict[str, object], *, keep: bool = False) -> None:  # type: ignore[no-untyped-def]
        wb(f"{case}/server.crt", pem(make_cert(key, f"{case}.test")), keep=keep)
        wb(f"{case}/server.key", pkcs8(key), keep=keep)
        body = {"cert": "server.crt", "key": "server.key", **spec}
        w(f"{case}/endpoint.yaml", json.dumps(body, indent=2, sort_keys=True))  # JSON is valid YAML

    endpoint("endpoint-tls10-only", seeded_rsa(2048, "ep-tls10"),
             {"min_version": "TLSv1", "max_version": "TLSv1", "ciphers": "DEFAULT:@SECLEVEL=0"})
    endpoint("endpoint-rsa-kex-only", seeded_rsa(2048, "ep-rsakex"),
             {"min_version": "TLSv1.2", "max_version": "TLSv1.2", "ciphers": "AES256-GCM-SHA384"})
    endpoint("endpoint-null-cipher", seeded_rsa(2048, "ep-null"),
             {"min_version": "TLSv1.2", "max_version": "TLSv1.2", "ciphers": "NULL-SHA256:@SECLEVEL=0"})
    # 3DES is compiled out of OpenSSL 3.x TLS, so this serves AES128-SHA there.
    endpoint("endpoint-cbc-sha1", seeded_rsa(2048, "ep-cbc-sha1"),
             {"min_version": "TLSv1.2", "max_version": "TLSv1.2", "ciphers": "DES-CBC3-SHA:AES128-SHA:@SECLEVEL=0"})
    endpoint("endpoint-tls12-ecdhe", seeded_rsa(2048, "ep-ecdhe"),
             {"min_version": "TLSv1.2", "max_version": "TLSv1.2", "ciphers": "ECDHE-RSA-AES128-GCM-SHA256"})
    endpoint("endpoint-mtls-tls12", seeded_rsa(2048, "ep-mtls"),
             {"min_version": "TLSv1.2", "max_version": "TLSv1.2", "ciphers": "ECDHE-RSA-AES256-GCM-SHA384",
              "require_client_cert": True})
    endpoint("endpoint-tls13-x25519", seeded_ec(ec.SECP256R1(), "ep-x25519"),
             {"min_version": "TLSv1.3", "max_version": "TLSv1.3", "group": "X25519"})
    # OpenSSL >= 3.5 offers X25519MLKEM768 first by default; older builds cannot host these.
    endpoint("endpoint-tls13-hybrid-ed25519", seeded_ed25519("ep-hybrid-ed"),
             {"min_version": "TLSv1.3", "max_version": "TLSv1.3", "requires_openssl": [3, 5]})
    endpoint("endpoint-tls13-hybrid-mldsa65", seeded_mldsa65("ep-hybrid-mldsa"),
             {"min_version": "TLSv1.3", "max_version": "TLSv1.3", "requires_openssl": [3, 5]}, keep=True)


# ----------------------------------------------------------------- OCI images
def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(files[name]), 0, 0o644
            tf.addfile(info, io.BytesIO(files[name]))
    return buf.getvalue()


def _blob(case: str, data: bytes, media_type: str) -> dict[str, object]:
    digest = hashlib.sha256(data).hexdigest()
    wb(f"{case}/blobs/sha256/{digest}", data)
    return {"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(data)}


def _canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def oci_image(case: str, files: dict[str, bytes]) -> None:
    """Single-layer OCI image layout (oci-layout, index.json, blobs/sha256/*)."""
    layer = _tar(files)
    layer_desc = _blob(case, layer, "application/vnd.oci.image.layer.v1.tar")
    config = {"architecture": "amd64", "os": "linux",
              "rootfs": {"type": "layers", "diff_ids": [layer_desc["digest"]]}}
    config_desc = _blob(case, _canon(config), "application/vnd.oci.image.config.v1+json")
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": config_desc, "layers": [layer_desc]}
    manifest_desc = _blob(case, _canon(manifest), "application/vnd.oci.image.manifest.v1+json")
    wb(f"{case}/oci-layout", _canon({"imageLayoutVersion": "1.0.0"}))
    wb(f"{case}/index.json", _canon({"schemaVersion": 2, "manifests": [manifest_desc]}))


def _fake_elf(banner: str) -> bytes:
    """ELF magic + header padding + an embedded version banner (what fs.binary.crypto reads)."""
    return b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56 + b"\x00" + banner.encode() + b"\x00"


_OPENSSL_CNF_LEGACY = (
    "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n"
    "[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n"
    "[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1\n"
)
_OPENSSL_CNF_DEFAULT = (
    "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\n\n"
    "[provider_sect]\ndefault = default_sect\n\n[default_sect]\nactivate = 1\n"
)


def image_fixtures() -> None:
    oci_image("image-legacy-openssl102", {
        "usr/lib/x86_64-linux-gnu/libssl.so.1.0.0": _fake_elf("OpenSSL 1.0.2u  20 Dec 2019"),
        "etc/ssl/openssl.cnf": _OPENSSL_CNF_LEGACY.encode(),
        "app/requirements.txt": b"flask==1.1.2\npycryptodome==3.9.0\n",
    })
    oci_image("image-modern-openssl35", {
        "usr/lib/x86_64-linux-gnu/libssl.so.3": _fake_elf("OpenSSL 3.5.0 8 Apr 2025"),
        "etc/ssl/openssl.cnf": _OPENSSL_CNF_DEFAULT.encode(),
        "app/requirements.txt": b"flask==3.0.3\nliboqs-python==0.10.0\n",
    })


# ------------------------------------------------------------ SQLite databases
def _build_db(rel: str, rows: list[tuple[str, str]]) -> None:
    path = CASES / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    try:
        con.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, blob TEXT)")
        con.executemany("INSERT INTO secrets (name, blob) VALUES (?, ?)", rows)
        con.commit()
    finally:
        con.close()


def db_fixtures() -> None:
    # A well-formed RSA-2048 cert as the PEM payload embedded in a DB column.
    db_cert = pem(make_cert(seeded_rsa(2048, "db-embedded"), "db-embedded.example"))
    _build_db("db-cert.db", [("tls-cert", db_cert.decode())])
    _build_db("db-clean.db", [
        ("note", "just some ordinary configuration text, no crypto here"),
        ("readme", "the quick brown fox jumps over the lazy dog"),
    ])


def write_hash() -> str:
    listing = run_benchmark.corpus_listing(CORPUS)
    (CORPUS / "CORPUS.sha256").write_text(listing)
    return hashlib.sha256(listing.encode()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hash", action="store_true", help="only rewrite CORPUS.sha256")
    args = parser.parse_args(argv)
    if not args.hash:
        text_fixtures()
        more_source_fixtures()
        cert_fixtures()
        key_fixtures()
        endpoint_fixtures()
        image_fixtures()
        db_fixtures()
        print("fixtures written to", CASES)
    print("corpus hash", write_hash())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
