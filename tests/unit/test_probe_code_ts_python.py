from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.core.confidence import assess
from pqcscan.core.types import Classification, Finding
from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_ts_python import CodeTsPython


async def _run(tmp_path: Path, filename: str, src: str) -> list[Finding]:
    (tmp_path / filename).write_text(src)
    found: list[Finding] = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=found.append)
    return found


@pytest.mark.asyncio
async def test_flags_md5_usage(tmp_path: Path):
    found = await _run(tmp_path, "app.py",
                       "import hashlib\n\nh = hashlib.md5(b'abc').hexdigest()\n")
    assert any("md5" in fnd.title.lower() for fnd in found)


# -- AST precision: comments & string literals must NOT be flagged -----------


@pytest.mark.asyncio
async def test_comment_only_produces_no_finding(tmp_path: Path):
    found = await _run(tmp_path, "c.py", "# hashlib.md5()  legacy\n")
    assert found == []


@pytest.mark.asyncio
async def test_string_literal_produces_no_finding(tmp_path: Path):
    found = await _run(tmp_path, "s.py", 'banner = "use hashlib.md5 for legacy"\n')
    assert found == []


# -- AST hits: precise, name-accurate, high confidence -----------------------


@pytest.mark.asyncio
async def test_md5_call_single_high_confidence(tmp_path: Path):
    found = await _run(tmp_path, "h.py", 'import hashlib\nhashlib.md5(b"x")\n')
    md5 = [f for f in found if f.algorithm == "MD5"]
    assert len(md5) == 1
    assert md5[0].classification is Classification.SANGAT_TINGGI
    assert md5[0].evidence["confidence"] == "high"


@pytest.mark.asyncio
async def test_alias_import_sha1(tmp_path: Path):
    found = await _run(tmp_path, "a.py", "import hashlib as h\nh.sha1(b'x')\n")
    sha1 = [f for f in found if f.algorithm == "SHA1"]
    assert len(sha1) == 1
    assert sha1[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_from_import_bare_md5(tmp_path: Path):
    found = await _run(tmp_path, "b.py", "from hashlib import md5\nmd5(b'x')\n")
    md5 = [f for f in found if f.algorithm == "MD5"]
    assert len(md5) == 1


@pytest.mark.asyncio
async def test_hashlib_new_weak_arg(tmp_path: Path):
    found = await _run(tmp_path, "n.py", 'import hashlib\nhashlib.new("md4")\n')
    assert any(f.algorithm == "MD4" for f in found)


@pytest.mark.asyncio
async def test_rsa_2048_sangat_tinggi_high_confidence(tmp_path: Path):
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    found = await _run(tmp_path, "r.py", src)
    rsa = [f for f in found if f.algorithm == "RSA-2048"]
    assert len(rsa) == 1
    assert rsa[0].classification is Classification.SANGAT_TINGGI
    assert rsa[0].evidence["confidence"] == "high"


@pytest.mark.asyncio
async def test_rsa_4096_tinggi(tmp_path: Path):
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )
    found = await _run(tmp_path, "r.py", src)
    rsa = [f for f in found if f.algorithm == "RSA-4096"]
    assert len(rsa) == 1
    assert rsa[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_rsa_non_literal_key_size(tmp_path: Path):
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "bits = 2048\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=bits)\n"
    )
    found = await _run(tmp_path, "r.py", src)
    rsa = [f for f in found if f.algorithm == "RSA"]
    assert len(rsa) == 1
    assert rsa[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_ec_keygen_classical(tmp_path: Path):
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP256R1())\n"
    )
    found = await _run(tmp_path, "e.py", src)
    hits = [f for f in found if f.evidence.get("kind") == "ecdsa_keygen"]
    assert len(hits) == 1
    assert hits[0].algorithm == "EC-SECP256R1"
    assert hits[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_des_cipher_sangat_tinggi(tmp_path: Path):
    src = "from Crypto.Cipher import DES\nc = DES.new(k, DES.MODE_ECB)\n"
    found = await _run(tmp_path, "d.py", src)
    des = [f for f in found if f.algorithm == "DES"]
    assert len(des) == 1
    assert des[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_weak_tls_protocol(tmp_path: Path):
    src = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
    found = await _run(tmp_path, "t.py", src)
    tls = [f for f in found if f.evidence.get("kind") == "weak_tls_proto"]
    assert len(tls) == 1
    assert tls[0].algorithm == "TLSv1"
    assert tls[0].classification is Classification.SANGAT_TINGGI


# -- regex fallback on unparseable (Python-2 / syntax error) files -----------


@pytest.mark.asyncio
async def test_syntax_error_falls_back_to_regex(tmp_path: Path):
    # `print "x"` is a Python-2 statement → SyntaxError under ast.parse.
    src = 'print "py2 banner"\nh = hashlib.md5(b"x")\n'
    found = await _run(tmp_path, "legacy.py", src)
    md5 = [f for f in found if f.algorithm == "MD5"]
    assert len(md5) == 1
    # No forced confidence on the finding; central model returns "medium".
    assert "confidence" not in md5[0].evidence
    assert assess(md5[0].probe_id, md5[0].evidence) == "medium"
