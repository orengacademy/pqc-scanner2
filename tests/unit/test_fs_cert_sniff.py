from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_sniff import FsCertSniff

_CTX = ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _make_cert(key_size: int, *, ca: bool) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sniff-test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(key, hashes.SHA256()), key


def _cert_pem(key_size: int = 2048, *, ca: bool = False) -> bytes:
    cert, _ = _make_cert(key_size, ca=ca)
    return cert.public_bytes(serialization.Encoding.PEM)


def _cert_der(key_size: int = 2048) -> bytes:
    cert, _ = _make_cert(key_size, ca=False)
    return cert.public_bytes(serialization.Encoding.DER)


def _key_pem(key_size: int = 2048) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


async def _run(root: Path) -> list:
    found: list = []
    probe = FsCertSniff(roots=[root])
    await probe.run(_CTX, emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_applies_when_root_exists(tmp_path: Path):
    probe = FsCertSniff(roots=[tmp_path])
    assert await probe.applies(_CTX) is True
    missing = FsCertSniff(roots=[tmp_path / "nope"])
    assert await missing.applies(_CTX) is False


@pytest.mark.asyncio
async def test_default_roots():
    probe = FsCertSniff()
    assert probe.roots == [Path("/etc"), Path("/opt"), Path("/srv")]


@pytest.mark.asyncio
async def test_pem_cert_in_txt_file_flagged(tmp_path: Path):
    (tmp_path / "config.txt").write_bytes(_cert_pem(2048))
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.probe_id == "fs.cert.sniff"
    assert f.classification is Classification.SANGAT_TINGGI  # RSA-2048 < 3072
    assert f.severity is Severity.HIGH  # weak -> HIGH
    assert "non-standard" in f.evidence["note"]
    assert f.evidence["kind"] == "certificate"


@pytest.mark.asyncio
async def test_classical_cert_is_med(tmp_path: Path):
    (tmp_path / "blob.dat").write_bytes(_cert_pem(3072))
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI  # RSA-3072 classical
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_der_cert_no_extension_flagged(tmp_path: Path):
    (tmp_path / "credential").write_bytes(_cert_der(2048))
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].evidence["kind"] == "certificate"


@pytest.mark.asyncio
async def test_private_key_in_conf_flagged(tmp_path: Path):
    (tmp_path / "service.conf").write_bytes(_key_pem(2048))
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED
    assert f.evidence["kind"] == "private-key"


@pytest.mark.asyncio
async def test_standard_extension_skipped(tmp_path: Path):
    # Same cert content but with a covered suffix — must NOT be flagged here.
    (tmp_path / "real.pem").write_bytes(_cert_pem(2048))
    (tmp_path / "real.key").write_bytes(_key_pem(2048))
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_ca_cert_skipped(tmp_path: Path):
    (tmp_path / "ca.txt").write_bytes(_cert_pem(2048, ca=True))
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_non_credential_file_ignored(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("just some plain text, no markers here\n")
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_oversize_file_skipped(tmp_path: Path):
    pem = _cert_pem(2048)
    padded = b"#" * 262145 + pem  # > _MAX_SIZE
    (tmp_path / "huge.txt").write_bytes(padded)
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_gated_but_unparseable_does_not_crash(tmp_path: Path):
    # Has the PEM marker but garbage body — must be caught, no finding, no crash.
    (tmp_path / "fake.txt").write_bytes(b"-----BEGIN CERTIFICATE-----\nnotbase64!!!\n")
    # Also a DER-magic file that is not a real structure.
    (tmp_path / "fake.bin").write_bytes(b"\x30\x82\x00\x05garbage")
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_unreadable_file_does_not_crash(tmp_path: Path):
    p = tmp_path / "locked.txt"
    p.write_bytes(_cert_pem(2048))
    p.chmod(0o000)
    try:
        found = await _run(tmp_path)
    finally:
        p.chmod(0o644)
    # Either skipped (unreadable) or read — must not raise. Length is 0 or 1.
    assert len(found) <= 1


@pytest.mark.asyncio
async def test_nested_directory_walked(tmp_path: Path):
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    (sub / "deep.txt").write_bytes(_cert_pem(2048))
    found = await _run(tmp_path)
    assert len(found) == 1
