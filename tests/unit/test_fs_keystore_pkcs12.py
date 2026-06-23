from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, ProbeFamily, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_x509 import FsCertX509
from pqcscan.probes.fs_keystore_pkcs12 import (
    FsKeystorePkcs12,
    _classify_sig_hash,
    _sev,
)


def _make_cert(key, hash_alg):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hash_alg)
    )


def _write_p12(path: Path, key, cert, password: bytes | None) -> None:
    enc = BestAvailableEncryption(password) if password else None
    data = pkcs12.serialize_key_and_certificates(
        name=b"test", key=key, cert=cert, cas=None,
        encryption_algorithm=enc or pkcs12.serialization.NoEncryption(),
    )
    path.write_bytes(data)


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(tmp_path: Path) -> list:
    found: list = []
    probe = FsKeystorePkcs12(roots=[tmp_path])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


def test_metadata_matches_conventions():
    p = FsKeystorePkcs12()
    assert p.id == "fs.keystore.pkcs12"
    assert p.family is ProbeFamily.FILESYSTEM
    # REUSE exact framework_tags from fs_cert_x509.
    assert p.framework_tags == FsCertX509().framework_tags
    assert p.roots == [Path("/etc/ssl"), Path("/etc/pki")]


@pytest.mark.asyncio
async def test_applies_when_root_exists(tmp_path: Path):
    p = FsKeystorePkcs12(roots=[tmp_path])
    assert await p.applies(_ctx()) is True
    missing = FsKeystorePkcs12(roots=[tmp_path / "nope"])
    assert await missing.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_rsa_1024_key_flagged_high(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = _make_cert(key, hashes.SHA256())
    _write_p12(tmp_path / "weak.p12", key, cert, None)
    found = await _run(tmp_path)
    key_finds = [f for f in found if f.evidence.get("kind") == "private-key"]
    assert len(key_finds) == 1
    f = key_finds[0]
    assert f.algorithm == "RSA-1024"
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.probe_id == "fs.keystore.pkcs12"


@pytest.mark.asyncio
async def test_ec_key_classified_modern_classical(tmp_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_cert(key, hashes.SHA256())
    _write_p12(tmp_path / "ec.pfx", key, cert, None)
    found = await _run(tmp_path)
    key_finds = [f for f in found if f.evidence.get("kind") == "private-key"]
    assert key_finds[0].algorithm == "EC-secp256r1"
    # EC is quantum-vulnerable but not broken -> TINGGI per classify().
    assert key_finds[0].classification is Classification.TINGGI


def test_sha1_md5_signature_classified_high():
    # Modern cryptography builds refuse to *create* SHA-1/MD5 signatures, so
    # exercise the classification helper directly (deterministic, no fixture).
    for name in ("SHA1", "sha-1", "MD5", "md5"):
        cls = _classify_sig_hash(name)
        assert cls is Classification.TINGGI
        assert _sev(cls) is Severity.HIGH
    assert _classify_sig_hash("SHA256") is Classification.INFO


@pytest.mark.asyncio
async def test_sha256_signature_info(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = _make_cert(key, hashes.SHA256())
    _write_p12(tmp_path / "ok.p12", key, cert, None)
    found = await _run(tmp_path)
    sig_finds = [f for f in found if f.evidence.get("kind") == "leaf-cert-signature"]
    assert sig_finds[0].algorithm == "SHA256"
    assert sig_finds[0].classification is Classification.INFO


@pytest.mark.asyncio
async def test_encrypted_with_known_password_loads(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(key, hashes.SHA256())
    _write_p12(tmp_path / "ks.p12", key, cert, b"changeit")
    found = await _run(tmp_path)
    # Decryptable with a tried password -> real key/sig findings, no "encrypted" note.
    kinds = {f.evidence.get("kind") for f in found}
    assert kinds == {"private-key", "leaf-cert-signature"}
    assert all(f.algorithm != "PKCS12-ENCRYPTED" for f in found)


@pytest.mark.asyncio
async def test_undecryptable_emits_encrypted_finding(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(key, hashes.SHA256())
    _write_p12(tmp_path / "secret.p12", key, cert, b"super-unguessable-secret")
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.algorithm == "PKCS12-ENCRYPTED"
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED


@pytest.mark.asyncio
async def test_malformed_file_does_not_crash(tmp_path: Path):
    (tmp_path / "junk.p12").write_bytes(b"not a real pkcs12 blob")
    found = await _run(tmp_path)
    # Garbage is undecryptable -> emits the encrypted/undecryptable inventory note.
    assert all(f.probe_id == "fs.keystore.pkcs12" for f in found)


@pytest.mark.asyncio
async def test_ignores_non_keystore_extensions(tmp_path: Path):
    (tmp_path / "readme.txt").write_bytes(b"hello")
    (tmp_path / "cert.pem").write_bytes(b"-----BEGIN CERTIFICATE-----")
    found = await _run(tmp_path)
    assert found == []
