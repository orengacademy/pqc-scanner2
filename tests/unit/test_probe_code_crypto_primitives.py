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


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("a.py", "x = 1  # hashlib.md5() is legacy\n"),
    ("a.py", 'msg = """\nnever use md5 here\n"""\n'),
    ("a.go", "// md5.New() must never be used here\nvar s = `md5 in raw`\n"),
    ("a.java", 'String s = """\n    MessageDigest.getInstance("MD5")\n""";\n'),
])
async def test_comment_and_prose_string_mentions_do_not_fire(tmp_path: Path, name: str, body: str):
    assert [f.algorithm for f in await _run(tmp_path, name, body)] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("A.java", 'MessageDigest md = MessageDigest.getInstance("MD5");\n'),   # bare token string = real use
    ("app.js", "const h = crypto.createHash('md5');\n"),
    ("a.py", "import hashlib\nd = hashlib.md5(b'x')\n"),
    ("a.rb", "d = Digest::MD5.hexdigest(data)\n"),
    ("a.c", "MD5(d, n, out);\n"),
])
async def test_real_use_still_fires(tmp_path: Path, name: str, body: str):
    assert "MD5" in [f.algorithm for f in await _run(tmp_path, name, body)]


@pytest.mark.asyncio
async def test_first_counting_occurrence_is_reported(tmp_path: Path):
    found = await _run(tmp_path, "a.py", "# md5 is banned\nimport hashlib\nd = hashlib.md5(b'x')\n")
    assert _by_alg(found, "MD5").evidence["line"] == 3



@pytest.mark.asyncio
async def test_stateful_hash_signatures_are_pqc_ready(tmp_path: Path):
    body = ('sig = oqs.Signature("XMSS-SHA2_10_256")\n'
            "kp = generate_lms_keypair()\ns = lms_sign(message, kp)\n"
            "# our LMS (learning management system) export\n")
    found = {f.algorithm: f.classification for f in await _run(tmp_path, "pqc.py", body)}
    assert found["XMSS"] is Classification.PQC_READY
    assert found["LMS"] is Classification.PQC_READY
    other = tmp_path / "other"
    other.mkdir()
    found = {f.algorithm for f in await _run(other, "lms.py", "course = lms.Course()  # LMS integration\n")}
    assert "LMS" not in found


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("a.rb", "# Digest::MD5 is banned\n"),
    ("a.c", "/* MD5() is banned */\n"),
    ("a.cpp", "// MD5() is banned\n"),
    ("a.swift", "// Insecure.MD5 is banned\n"),
])
async def test_untrusted_lexers_fail_open(tmp_path: Path, name: str, body: str):
    # No comment/string stripping for C/C++, Ruby or Swift: a mention fires.
    assert "MD5" in [f.algorithm for f in await _run(tmp_path, name, body)]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("app.js", "const s = `${md5(x)}`;\n"),
    ("app.ts", "const s = `digest: ${createHash('md5').digest('hex')}`;\n"),
    ("a.py", 'import hashlib\ns = f"{hashlib.md5(b)}"\n'),
    ("a.py", 's = rf"{hashlib.md5(b)}"\n'),
    ("A.kt", 'val s = "${MessageDigest.getInstance(alg).digest()} md5"\n'),
    ("a.php", '<?php\n$s = "hash: {$md5($x)}";\n'),
    ("A.cs", 'var s = $"hash {MD5.Create().ComputeHash(d)}";\n'),
])
async def test_interpolated_literals_count_as_code(tmp_path: Path, name: str, body: str):
    assert "MD5" in [f.algorithm for f in await _run(tmp_path, name, body)]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("a.rb", "ok = line =~ /md5/ # legacy check\nd = Digest::MD5.hexdigest(x)\n"),
    ("a.swift", 'let s = #"md5"#; let d = Insecure.MD5.hash(data: x)\n'),
])
async def test_crafted_literals_do_not_hide_real_use(tmp_path: Path, name: str, body: str):
    assert "MD5" in [f.algorithm for f in await _run(tmp_path, name, body)]



@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body", "expected"), [
    ("S.java", 'Signature s = Signature.getInstance("LMS");\n', True),
    ("K.java", 'KeyPairGenerator g = KeyPairGenerator.getInstance("LMS");\n', True),
    ("s.py", 'sig = oqs.Signature("LMS")\n', True),
    ("r.py", 'report.title("LMS")\n', False),     # not a crypto call
])
async def test_bare_lms_string_in_a_crypto_call(tmp_path: Path, name: str, body: str, expected: bool):
    assert ("LMS" in [f.algorithm for f in await _run(tmp_path, name, body)]) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("app.js", "const r = /\"/; const h = crypto.createHash('md5'); const s = \"y\";\n"),
    ("app.ts", "const r = /'/; const h = crypto.createHash(\"md5\"); const s = 'y';\n"),
    ("a.py", "s = f\"{'\"'}\"; h = hashlib.md5(b); t = 'x'\n"),                 # Python 3.12 f-string
    ("A.cs", 'var a = """a\\"""; var h = MD5.Create(); var s = "x";\n'),       # C# 11 raw string
    ("A.kt", 'val a = "${"\\""}"; val d = MessageDigest.getInstance(md5); val s = "y"\n'),
])
async def test_stray_quote_cannot_swallow_a_real_call(tmp_path: Path, name: str, body: str):
    # One misread construct opens a "string" at a stray quote; the statement it
    # swallows holds a primitive in call context plus code punctuation -> code.
    assert "MD5" in [f.algorithm for f in await _run(tmp_path, name, body)]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "body"), [
    ("a.php", '<?php\n$note = "md5($password) is forbidden";\n'),
    ("A.cs", 'class C { string s = "never call MD5.Create() here"; }\n'),
    ("app.js", 'const note = "crypto.createHash(\'md5\') is forbidden";\n'),
    ("a.py", 'label = "use hashlib.md5 for the checksum"\n'),
])
async def test_prose_quoting_a_call_stays_suppressed(tmp_path: Path, name: str, body: str):
    assert "MD5" not in [f.algorithm for f in await _run(tmp_path, name, body)]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["a.h", "a.hpp", "a.cc", "a.cxx"])
async def test_more_c_cpp_suffixes_are_scanned_unstripped(tmp_path: Path, name: str):
    assert "MD5" in [f.algorithm for f in await _run(tmp_path, name, "// MD5() is banned\n")]



@pytest.mark.asyncio
async def test_large_literal_with_many_tokens_is_linear(tmp_path: Path):
    import time

    # A 1 MiB single string literal holding 10,000 md5( tokens must cost about the
    # same as a 1 MiB literal with none: the span verdict is computed once, and a
    # span over 64 kB counts as code without inspection. (Absolute time is the
    # probe's own ~40-pattern pass over 1 MiB, ~1.2 s here; before the memo the
    # token file took ~15 s.)
    async def scan(name: str, body: str) -> tuple[float, list[Finding]]:
        d = tmp_path / name
        d.mkdir()
        (d / "app.js").write_text('const s = "' + body + '";\n')
        found: list[Finding] = []
        t0 = time.perf_counter()
        await CodeCryptoPrimitives(roots=[d]).run(_ctx([d]), emit=found.append)
        return time.perf_counter() - t0, found

    t_plain, _ = await scan("plain", ("xxxx " + "x" * 100) * 10_000)
    t_tokens, found = await scan("tokens", ("md5( " + "x" * 100) * 10_000)
    assert t_tokens < 3 * t_plain + 1.0, (t_tokens, t_plain)   # quadratic was ~12x
    assert "MD5" in [f.algorithm for f in found]   # over the inspection cap: fail open


@pytest.mark.asyncio
async def test_span_verdict_is_computed_once(tmp_path: Path, monkeypatch):
    from pqcscan.probes import code_crypto_primitives as mod

    calls: list[int] = []
    real = mod._holds_call

    def counting(body: str) -> bool:
        calls.append(len(body))
        return real(body)

    monkeypatch.setattr(mod, "_holds_call", counting)
    # one prose span with punctuation and many tokens, none in call context
    await _run(tmp_path, "app.js", 'const s = "' + "md5, " * 500 + '";\n')
    assert len(calls) == 1
