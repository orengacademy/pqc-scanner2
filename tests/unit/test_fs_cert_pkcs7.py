from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, ProbeFamily, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_pkcs7 import FsCertPkcs7


def _cert(key, cn: str, sig_hash) -> x509.Certificate:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    return builder.sign(key, sig_hash)


def _write_bundle(path: Path, certs: list[x509.Certificate], encoding: Encoding) -> None:
    path.write_bytes(pkcs7.serialize_certificates(certs, encoding))


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(probe: FsCertPkcs7) -> list:
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


def test_metadata_matches_conventions():
    p = FsCertPkcs7()
    assert p.id == "fs.cert.pkcs7"
    assert p.family is ProbeFamily.FILESYSTEM
    assert p.framework_tags == ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")


def test_default_roots():
    assert FsCertPkcs7().roots == [Path("/etc/ssl"), Path("/etc/pki")]


@pytest.mark.asyncio
async def test_applies_false_when_no_roots(tmp_path: Path):
    probe = FsCertPkcs7(roots=[tmp_path / "missing"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path: Path):
    probe = FsCertPkcs7(roots=[tmp_path])
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_rsa_2048_pem_flagged_high_or_worse(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_bundle(tmp_path / "bundle.p7b", [_cert(key, "rsa2048", hashes.SHA256())], Encoding.PEM)
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    assert len(found) == 1
    f = found[0]
    # RSA <3072 is Sangat Tinggi per classify(); never below HIGH.
    assert f.severity.numeric >= Severity.HIGH.numeric
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.evidence["key_algorithm"] == "RSA-2048"
    assert f.evidence["subject"] == "rsa2048"


@pytest.mark.asyncio
async def test_sha1_signature_flagged(tmp_path: Path):
    # Strong-ish key but SHA-1 signature -> weak signature outranks.
    # Modern `cryptography` refuses to *create* SHA-1 sigs, so mint the cert
    # with the openssl CLI, then bundle it as PKCS#7.
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    keyp = tmp_path / "k.pem"
    certp = tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-sha1", "-newkey", "rsa:3072", "-nodes",
         "-keyout", str(keyp), "-out", str(certp), "-days", "1", "-subj", "/CN=sha1cert"],
        check=True, capture_output=True,
    )
    cert = x509.load_pem_x509_certificate(certp.read_bytes())
    _write_bundle(tmp_path / "sha1.p7c", [cert], Encoding.DER)
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    f = next(x for x in found if x.evidence["subject"] == "sha1cert")
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.evidence["signature_algorithm"] == "SHA-1"


@pytest.mark.asyncio
async def test_ecdsa_modern_classical(tmp_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    _write_bundle(tmp_path / "ec.p7b", [_cert(key, "eccert", hashes.SHA256())], Encoding.PEM)
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    assert len(found) == 1
    f = found[0]
    # ECDSA is quantum-vulnerable but not broken -> TINGGI/HIGH.
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH
    assert f.evidence["key_algorithm"].startswith("ECDSA-")


@pytest.mark.asyncio
async def test_ed25519_modern_classical(tmp_path: Path):
    key = ed25519.Ed25519PrivateKey.generate()
    # Ed25519 self-sign: signature_hash_algorithm is None.
    cert = _cert(key, "edcert", None)
    _write_bundle(tmp_path / "ed.p7b", [cert], Encoding.PEM)
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.TINGGI
    assert f.evidence["key_algorithm"] == "Ed25519"
    assert f.evidence["signature_algorithm"] is None


@pytest.mark.asyncio
async def test_multiple_certs_in_bundle(tmp_path: Path):
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    k2 = ec.generate_private_key(ec.SECP384R1())
    certs = [_cert(k1, "first", hashes.SHA256()), _cert(k2, "second", hashes.SHA384())]
    _write_bundle(tmp_path / "chain.p7b", certs, Encoding.PEM)
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    assert len(found) == 2
    subjects = {f.evidence["subject"] for f in found}
    assert subjects == {"first", "second"}


@pytest.mark.asyncio
async def test_malformed_file_skipped(tmp_path: Path):
    (tmp_path / "garbage.p7b").write_bytes(b"not a pkcs7 bundle at all")
    (tmp_path / "empty.p7c").write_bytes(b"")
    # Should not raise; just yields nothing.
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    assert found == []


@pytest.mark.asyncio
async def test_ignores_non_pkcs7_extensions(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data = pkcs7.serialize_certificates([_cert(key, "x", hashes.SHA256())], Encoding.PEM)
    (tmp_path / "bundle.pem").write_bytes(data)  # wrong extension
    found = await _run(FsCertPkcs7(roots=[tmp_path]))
    assert found == []


@pytest.mark.asyncio
async def test_missing_root_is_skipped(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_bundle(tmp_path / "b.p7b", [_cert(key, "z", hashes.SHA256())], Encoding.PEM)
    probe = FsCertPkcs7(roots=[tmp_path / "nope", tmp_path])
    found = await _run(probe)
    assert len(found) == 1
