"""One-time fixture generator for the accuracy benchmark corpus.

Writes text source/config fixtures plus binary cert PEMs and SQLite DBs into
benchmark/corpus/cases/. Re-runnable; overwrites deterministically.
"""
from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, rsa
from cryptography.hazmat.primitives.serialization import Encoding

REPO = Path("/home/ubuntu/Projects/pqc-scanner2")
CASES = REPO / "benchmark" / "corpus" / "cases"


def w(rel: str, text: str) -> None:
    p = CASES / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text if text.endswith("\n") else text + "\n")


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


# ---------------------------------------------------------- certs (binary PEM)
def _cert(pubkey_holder, sigkey, halg, cn: str) -> bytes:
    sub = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2024, 1, 1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(sub)
        .public_key(pubkey_holder.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=800))
    )
    cert = builder.sign(sigkey, halg)
    return cert.public_bytes(Encoding.PEM)


_rsa1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
_rsa_cert_pem = _cert(_rsa1024, _rsa1024, hashes.SHA256(), "weak-rsa1024.example")
w("cert-rsa1024/server.pem", _rsa_cert_pem.decode())

_mldsa = mldsa.MLDSA65PrivateKey.generate()
_mldsa_cert_pem = _cert(_mldsa, _mldsa, None, "pqc-mldsa65.example")
w("cert-mldsa65/server.pem", _mldsa_cert_pem.decode())

# A well-formed RSA-2048 cert reused as the PEM payload embedded in a DB column.
_rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_db_cert_pem = _cert(_rsa2048, _rsa2048, hashes.SHA256(), "db-embedded.example")


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


_build_db("db-cert.db", [("tls-cert", _db_cert_pem.decode())])
_build_db("db-clean.db", [
    ("note", "just some ordinary configuration text, no crypto here"),
    ("readme", "the quick brown fox jumps over the lazy dog"),
])

print("fixtures written to", CASES)
