"""Tests for B14 source-code probes (JS, Go, Java, PHP, Rust)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_ts_go import CodeTsGo
from pqcscan.probes.code_ts_java import CodeTsJava
from pqcscan.probes.code_ts_javascript import CodeTsJavascript
from pqcscan.probes.code_ts_php import CodeTsPhp
from pqcscan.probes.code_ts_rust import CodeTsRust


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (CodeTsJavascript, "code.ts.javascript"),
        (CodeTsGo,         "code.ts.go"),
        (CodeTsJava,       "code.ts.java"),
        (CodeTsPhp,        "code.ts.php"),
        (CodeTsRust,       "code.ts.rust"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.CODE


@pytest.mark.asyncio
async def test_javascript_flags_md5_and_rsa_2048(tmp_path: Path):
    src = tmp_path / "app.js"
    src.write_text(
        "const crypto = require('crypto');\n"
        "const h = crypto.createHash('md5').update('x').digest('hex');\n"
        "const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', "
        "{ modulusLength: 2048 });\n"
    )
    found: list = []
    p = CodeTsJavascript(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("MD5" in t for t in titles)
    assert any("RSA-2048" in (f.algorithm or "") for f in found)
    assert any(f.algorithm == "RSA-2048"
               and f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_go_flags_md5_and_des_and_rsa(tmp_path: Path):
    src = tmp_path / "main.go"
    src.write_text(
        "package main\n"
        "import (\"crypto/md5\"; \"crypto/des\"; \"crypto/rsa\"; \"crypto/rand\")\n"
        "func main() {\n"
        "  _ = md5.New()\n"
        "  _, _ = des.NewCipher([]byte(\"x\"))\n"
        "  _, _ = rsa.GenerateKey(rand.Reader, 2048)\n"
        "}\n"
    )
    found: list = []
    p = CodeTsGo(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    algs = {f.algorithm for f in found}
    assert "MD5" in algs
    assert "DES" in algs
    assert "RSA-2048" in algs


@pytest.mark.asyncio
async def test_java_flags_messagedigest_md5_and_des(tmp_path: Path):
    src = tmp_path / "Crypto.java"
    src.write_text(
        "import java.security.MessageDigest;\n"
        "import javax.crypto.Cipher;\n"
        "MessageDigest.getInstance(\"MD5\");\n"
        "Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\n"
    )
    found: list = []
    p = CodeTsJava(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    algs = {f.algorithm.upper() for f in found}
    assert "MD5" in algs
    assert any("DES" in a for a in algs)


@pytest.mark.asyncio
async def test_php_flags_md5_and_mcrypt(tmp_path: Path):
    src = tmp_path / "weak.php"
    src.write_text(
        "<?php\n"
        "$h = md5('x');\n"
        "$h2 = hash('sha1', 'x');\n"
        "$enc = mcrypt_encrypt($cipher, $key, $data, MCRYPT_MODE_CBC);\n"
    )
    found: list = []
    p = CodeTsPhp(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    algs = {f.algorithm for f in found}
    assert "MD5" in algs
    assert "SHA1" in algs
    assert "MCRYPT" in algs


@pytest.mark.asyncio
async def test_rust_flags_md5_and_des(tmp_path: Path):
    src = tmp_path / "lib.rs"
    src.write_text(
        "use md5::Digest;\n"
        "let cipher = Des::new(&key);\n"
        "let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();\n"
    )
    found: list = []
    p = CodeTsRust(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    algs = {f.algorithm for f in found}
    assert "MD5" in algs
    assert "DES" in algs
    assert "RSA-2048" in algs
