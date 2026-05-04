"""Expanded code.ts.python tests — RSA / DSA / DES / AES-CBC patterns."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_ts_python import CodeTsPython


@pytest.mark.asyncio
async def test_flags_rsa_2048_generation_via_hazmat(tmp_path: Path):
    src = tmp_path / "keys.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    rsa_findings = [f for f in found if "RSA-2048" in f.algorithm]
    assert rsa_findings
    assert all(f.classification is Classification.SANGAT_TINGGI for f in rsa_findings)


@pytest.mark.asyncio
async def test_flags_rsa_4096_as_tinggi_not_sangat_tinggi(tmp_path: Path):
    src = tmp_path / "keys.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    rsa_findings = [f for f in found if "RSA-4096" in f.algorithm]
    assert rsa_findings
    assert all(f.classification is Classification.TINGGI for f in rsa_findings)


@pytest.mark.asyncio
async def test_flags_pycryptodome_rsa_generate(tmp_path: Path):
    src = tmp_path / "keys.py"
    src.write_text(
        "from Crypto.PublicKey import RSA\n"
        "key = RSA.generate(2048)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any("RSA-2048" in f.algorithm
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_flags_dsa_generation(tmp_path: Path):
    src = tmp_path / "keys.py"
    src.write_text(
        "from Crypto.PublicKey import DSA\n"
        "key = DSA.generate(1024)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "DSA"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_flags_des_cipher(tmp_path: Path):
    src = tmp_path / "cipher.py"
    src.write_text(
        "from Crypto.Cipher import DES\n"
        "c = DES.new(b'abcdefgh', DES.MODE_ECB)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "DES"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_flags_3des(tmp_path: Path):
    src = tmp_path / "cipher.py"
    src.write_text(
        "from Crypto.Cipher import DES3\n"
        "c = DES3.new(b'24bytekey...padpadpadpad', DES3.MODE_CBC)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "3DES" for f in found)


@pytest.mark.asyncio
async def test_flags_aes_cbc(tmp_path: Path):
    src = tmp_path / "cipher.py"
    src.write_text(
        "from Crypto.Cipher import AES\n"
        "c = AES.new(b'k'*32, AES.MODE_CBC, iv=b'i'*16)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any("AES-CBC" in f.algorithm
               and f.classification is Classification.TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_md5_still_flagged(tmp_path: Path):
    src = tmp_path / "hash.py"
    src.write_text("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n")
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "MD5"
               and f.classification is Classification.SANGAT_TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_no_findings_for_modern_code(tmp_path: Path):
    src = tmp_path / "modern.py"
    src.write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "h = hashlib.sha256(b'x').hexdigest()\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )
    found: list = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    # 4096-bit RSA still triggers Tinggi; sha256 doesn't trigger anything.
    assert all(f.algorithm.startswith("RSA-4096") for f in found)
