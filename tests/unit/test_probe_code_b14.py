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


# --- Comment / string-literal false-positive suppression ---------------------
# For each language: the same weak token that fires in real code must NOT fire
# when it lives inside a comment or inside a string literal.


async def _findings(probe_cls, tmp_path: Path, filename: str, source: str) -> list:
    (tmp_path / filename).write_text(source)
    found: list = []
    p = probe_cls(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_javascript_ignores_comment_and_string(tmp_path: Path):
    in_comment = await _findings(
        CodeTsJavascript, tmp_path, "c.js",
        "// crypto.createHash('md5') left in a comment\n"
        "/* crypto.createHash('sha1') block */\n",
    )
    assert in_comment == []
    in_string = await _findings(
        CodeTsJavascript, tmp_path, "s.js",
        "const doc = \"crypto.createHash('md5') mentioned in a string\";\n",
    )
    assert in_string == []


@pytest.mark.asyncio
async def test_go_ignores_comment_and_string(tmp_path: Path):
    in_comment = await _findings(
        CodeTsGo, tmp_path, "c.go",
        "package main\n// md5.New() in a comment\nfunc f() {}\n",
    )
    assert in_comment == []
    in_string = await _findings(
        CodeTsGo, tmp_path, "s.go",
        "package main\nvar s = \"md5.New() in a string\"\nvar r = `des.NewCipher raw`\n",
    )
    assert in_string == []


@pytest.mark.asyncio
async def test_java_ignores_comment_and_string(tmp_path: Path):
    in_comment = await _findings(
        CodeTsJava, tmp_path, "C.java",
        "// MessageDigest.getInstance(\"MD5\") in a comment\n"
        "/* Cipher.getInstance(\"DES/ECB/PKCS5Padding\") block */\n",
    )
    assert in_comment == []
    in_string = await _findings(
        CodeTsJava, tmp_path, "S.java",
        "String s = \"MessageDigest.getInstance(\\\"MD5\\\") in a string\";\n",
    )
    assert in_string == []


@pytest.mark.asyncio
async def test_php_ignores_comment_and_string(tmp_path: Path):
    in_comment = await _findings(
        CodeTsPhp, tmp_path, "c.php",
        "<?php\n// md5('x') in a comment\n# hash('sha1', 'x') hash comment\n",
    )
    assert in_comment == []
    in_string = await _findings(
        CodeTsPhp, tmp_path, "s.php",
        "<?php\n$note = \"md5('x') and mcrypt_encrypt() inside a string\";\n",
    )
    assert in_string == []


@pytest.mark.asyncio
async def test_rust_ignores_comment_and_string(tmp_path: Path):
    in_comment = await _findings(
        CodeTsRust, tmp_path, "c.rs",
        "// Des::new(&key) in a comment\n/* Rc4::new() block */\n",
    )
    assert in_comment == []
    in_string = await _findings(
        CodeTsRust, tmp_path, "s.rs",
        "let s = \"Des::new(&key) inside a string\";\n",
    )
    assert in_string == []
