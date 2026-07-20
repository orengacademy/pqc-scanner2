"""Tests for code.crypto_primitives (cross-language crypto primitive scanner)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_crypto_primitives import PRIMITIVE_PATTERNS, CodeCryptoPrimitives


def _ctx(paths: list[Path] | None = None) -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        scan_paths=paths or [],
    )


async def _run(tmp_path: Path, name: str, body: str) -> list[Finding]:
    (tmp_path / name).write_text(body)
    found: list[Finding] = []
    probe = CodeCryptoPrimitives(roots=[tmp_path])
    await probe.run(_ctx([tmp_path]), emit=lambda f: found.append(f))
    return found


def _by_alg(found: list[Finding], alg: str) -> Finding:
    matches = [f for f in found if f.algorithm == alg]
    assert matches, f"no finding for {alg!r}; got {[f.algorithm for f in found]}"
    return matches[0]


def test_probe_metadata():
    probe = CodeCryptoPrimitives()
    assert probe.id == "code.crypto_primitives"
    assert probe.family is ProbeFamily.CODE
    assert probe.framework_tags == ("nist-ir-8547:code", "mykripto:code")


@pytest.mark.asyncio
async def test_aes_ecb_python_is_sangat_tinggi(tmp_path: Path):
    found = await _run(tmp_path, "enc.py", "cipher = AES.new(key, AES.MODE_ECB)\n")
    f = _by_alg(found, "AES-ECB")
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.evidence["file"].endswith("enc.py")
    assert f.evidence["line"] == 1
    assert "ECB" in f.evidence["snippet"]


@pytest.mark.asyncio
async def test_ed25519_go_is_tinggi(tmp_path: Path):
    found = await _run(tmp_path, "keys.go", "pub, priv, _ := ed25519.GenerateKey(rand.Reader)\n")
    f = _by_alg(found, "Ed25519")
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_pqc_rust_is_pqc_ready(tmp_path: Path):
    body = "use pqcrypto::kyber768;\nlet (pk, sk) = kyber768::keypair();\n"
    found = await _run(tmp_path, "pq.rs", body)
    for alg in ("ML-KEM", "liboqs/pqcrypto"):
        f = _by_alg(found, alg)
        assert f.classification is Classification.PQC_READY
        assert f.severity is Severity.INFO


@pytest.mark.asyncio
async def test_3des_java_is_sangat_tinggi(tmp_path: Path):
    body = 'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n'
    found = await _run(tmp_path, "Legacy.java", body)
    f = _by_alg(found, "3DES")
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT


@pytest.mark.asyncio
async def test_weak_hashes_php(tmp_path: Path):
    found = await _run(tmp_path, "hash.php", "<?php echo md5($x); echo sha1($y);\n")
    assert _by_alg(found, "MD5").classification is Classification.SANGAT_TINGGI
    assert _by_alg(found, "SHA-1").classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_rsa_2048_keygen_is_sangat_tinggi(tmp_path: Path):
    body = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    found = await _run(tmp_path, "rsa.py", body)
    f = _by_alg(found, "RSA-2048")
    assert f.classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_rsa_4096_keygen_is_tinggi(tmp_path: Path):
    found = await _run(tmp_path, "rsa4k.py", "priv = RSA.generate(4096)\n")
    f = _by_alg(found, "RSA-3072/4096")
    assert f.classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_curve_and_padding_ts(tmp_path: Path):
    body = 'const curve = "secp256r1"; const pad = "OAEP";\n'
    found = await _run(tmp_path, "ec.ts", body)
    assert _by_alg(found, "P-256 (secp256r1)").classification is Classification.TINGGI
    assert _by_alg(found, "RSA-OAEP").classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_aes_gcm_and_chacha20_are_low_tier(tmp_path: Path):
    body = "c1 = AES-256-GCM; c2 = ChaCha20;\n"
    found = await _run(tmp_path, "aead.rb", body)
    assert _by_alg(found, "AES-256-GCM").classification is Classification.RENDAH
    assert _by_alg(found, "ChaCha20").classification is Classification.RENDAH


@pytest.mark.asyncio
async def test_dedup_same_algorithm_within_file(tmp_path: Path):
    body = "a = md5(x)\nb = md5(y)\nc = md5(z)\n"
    found = await _run(tmp_path, "dup.cpp", body)
    md5s = [f for f in found if f.algorithm == "MD5"]
    assert len(md5s) == 1


@pytest.mark.asyncio
async def test_clean_file_yields_no_findings(tmp_path: Path):
    found = await _run(tmp_path, "plain.py", "def add(a, b):\n    return a + b\n")
    assert found == []


@pytest.mark.asyncio
async def test_applies_false_without_scan_paths(tmp_path: Path):
    probe = CodeCryptoPrimitives()
    assert await probe.applies(_ctx([])) is False


@pytest.mark.asyncio
async def test_applies_true_with_scan_paths(tmp_path: Path):
    probe = CodeCryptoPrimitives()
    assert await probe.applies(_ctx([tmp_path])) is True


def test_all_patterns_compiled_once():
    # Sanity: corpus is a non-trivial, compiled, reviewable list.
    assert len(PRIMITIVE_PATTERNS) >= 25
    for pattern, algorithm, classification in PRIMITIVE_PATTERNS:
        assert hasattr(pattern, "search")
        assert isinstance(algorithm, str) and algorithm
        assert isinstance(classification, Classification)
