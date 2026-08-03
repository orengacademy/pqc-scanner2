from pathlib import Path

from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_ts_csharp import CodeTsCsharp


def _ctx() -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        scan_paths=[], server_target=None, ot_targets=[], sniff=None,
    )


def _scan(tmp_path: Path, source: str) -> list:
    import asyncio

    (tmp_path / "Crypto.cs").write_text(source)
    findings: list = []
    probe = CodeTsCsharp(roots=[tmp_path])
    asyncio.run(probe.run(_ctx(), findings.append))
    return findings


def _algs(findings) -> set[str]:
    return {f.algorithm for f in findings}


def test_md5_create_flagged_crit(tmp_path):
    f = _scan(tmp_path, "var h = MD5.Create();")
    assert any(x.algorithm == "MD5" and x.classification.value == "sangat-tinggi" for x in f)


def test_sha1_managed_ctor_flagged(tmp_path):
    f = _scan(tmp_path, "var h = new SHA1Managed();")
    assert "SHA1" in _algs(f)


def test_named_create_string_arg_flagged(tmp_path):
    # Anchored on HashAlgorithm.Create (real code), so string-blanking in the
    # non-code stripper must not hide it.
    f = _scan(tmp_path, 'var h = HashAlgorithm.Create("MD5");')
    assert "MD5" in _algs(f)


def test_triple_des_and_rc2_flagged_crit(tmp_path):
    f = _scan(tmp_path, "var a = new TripleDESCryptoServiceProvider();\n"
                        "var b = new RC2CryptoServiceProvider();")
    algs = _algs(f)
    assert "TRIPLEDES" in algs and "RC2" in algs
    assert all(x.classification.value == "sangat-tinggi"
               for x in f if x.algorithm in {"TRIPLEDES", "RC2"})


def test_rsa_with_small_modulus_is_crit(tmp_path):
    f = _scan(tmp_path, "var k = new RSACryptoServiceProvider(1024);")
    hits = [x for x in f if x.algorithm == "RSA-1024"]
    assert hits and hits[0].classification.value == "sangat-tinggi"


def test_rsa_2048_is_crit_below_cnsa_floor(tmp_path):
    # RSA < 3072 bits is SANGAT_TINGGI per core/alg.py (CNSA 2.0 floor).
    f = _scan(tmp_path, "var k = RSA.Create(2048);")
    hits = [x for x in f if x.algorithm == "RSA-2048"]
    assert hits and hits[0].classification.value == "sangat-tinggi"


def test_rsa_4096_is_tinggi(tmp_path):
    f = _scan(tmp_path, "var k = new RSACryptoServiceProvider(4096);")
    hits = [x for x in f if x.algorithm == "RSA-4096"]
    assert hits and hits[0].classification.value == "tinggi"


def test_bare_rsa_create_defaults_to_crit(tmp_path):
    # Default key size is 2048 → below the floor → SANGAT_TINGGI.
    f = _scan(tmp_path, "var k = RSA.Create();")
    assert any(x.algorithm == "RSA-2048" and x.classification.value == "sangat-tinggi" for x in f)


def test_dsa_flagged(tmp_path):
    f = _scan(tmp_path, "var k = new DSACryptoServiceProvider();")
    assert "DSA" in _algs(f)


def test_ecdsa_is_tinggi_shor(tmp_path):
    f = _scan(tmp_path, "var k = ECDsa.Create();")
    hits = [x for x in f if x.algorithm == "ECDSA"]
    assert hits and hits[0].classification.value == "tinggi"


def test_ecb_mode_flagged_crit(tmp_path):
    f = _scan(tmp_path, "aes.Mode = CipherMode.ECB;")
    hits = [x for x in f if "ECB" in x.algorithm]
    assert hits and hits[0].classification.value == "sangat-tinggi"


def test_comment_and_string_are_not_flagged(tmp_path):
    src = (
        "// legacy MD5.Create() left for reference\n"
        'string note = "we removed new DESCryptoServiceProvider() calls";\n'
        "var ok = SHA256.Create();\n"
    )
    f = _scan(tmp_path, src)
    assert not f, f"expected no findings, got {_algs(f)}"


def test_verbatim_string_path_not_flagged(tmp_path):
    # A Windows path in a verbatim string must not trip the DES matcher.
    f = _scan(tmp_path, r'var p = @"C:\DES\keys.txt";')
    assert not f


def test_sha256_and_aes_not_flagged(tmp_path):
    f = _scan(tmp_path, "var h = SHA256.Create();\nvar a = Aes.Create();")
    assert not f


def test_registered_in_default_registry():
    from pqcscan.probes._registry import default_registry
    assert "code.ts.csharp" in default_registry().ids()


# ---- standards-currency regression guard (gap B: already in core/alg.py) ----

def test_hqc_and_fndsa_classify_as_pqc_ready():
    from pqcscan.core.alg import classify
    for name in ("HQC-128", "HQC-256", "FN-DSA-512", "Falcon-1024", "ML-KEM-768"):
        assert classify(name).value == "pqc-ready", name
