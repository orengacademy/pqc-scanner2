from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_expiry_horizon import (
    CRQC_DEADLINE,
    HNDL_DEADLINE,
    FsCertExpiryHorizon,
)


def _write_cert(
    path: Path,
    not_after: datetime,
    *,
    key: object | None = None,
    encoding: str = "pem",
) -> None:
    priv = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(not_after)
    )
    cert = builder.sign(priv, hashes.SHA256())
    from cryptography.hazmat.primitives.serialization import Encoding

    enc = Encoding.PEM if encoding == "pem" else Encoding.DER
    path.write_bytes(cert.public_bytes(enc))


async def _run(tmp_path: Path) -> list:
    found: list = []
    probe = FsCertExpiryHorizon(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    return found


def test_module_deadlines():
    assert HNDL_DEADLINE.year == 2030
    assert CRQC_DEADLINE.year == 2035


@pytest.mark.asyncio
async def test_past_crqc_horizon_is_tinggi_high(tmp_path: Path):
    _write_cert(tmp_path / "c.pem", datetime(2036, 6, 1, tzinfo=UTC))
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH
    assert f.probe_id == "fs.cert.expiry_horizon"
    assert "harvest-now-decrypt-later" in f.title


@pytest.mark.asyncio
async def test_between_hndl_and_crqc_is_sederhana_med(tmp_path: Path):
    _write_cert(tmp_path / "c.pem", datetime(2032, 1, 1, tzinfo=UTC))
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_before_hndl_is_rendah_low(tmp_path: Path):
    _write_cert(tmp_path / "c.pem", datetime(2028, 1, 1, tzinfo=UTC))
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.RENDAH
    assert found[0].severity is Severity.LOW


@pytest.mark.asyncio
async def test_ec_key_classified_as_classical(tmp_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    _write_cert(tmp_path / "c.pem", datetime(2040, 1, 1, tzinfo=UTC), key=key)
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].algorithm.startswith("ECDSA-")


@pytest.mark.asyncio
async def test_der_encoded_cert_parsed(tmp_path: Path):
    _write_cert(
        tmp_path / "c.cer",
        datetime(2036, 1, 1, tzinfo=UTC),
        encoding="der",
    )
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_evidence_records_deadlines_and_path(tmp_path: Path):
    cpath = tmp_path / "c.pem"
    _write_cert(cpath, datetime(2037, 1, 1, tzinfo=UTC))
    found = await _run(tmp_path)
    ev = found[0].evidence
    assert ev["path"] == str(cpath)
    assert ev["not_after"].startswith("2037")
    assert ev["hndl_deadline"] == "2030-01-01"
    assert ev["crqc_deadline"] == "2035-01-01"


@pytest.mark.asyncio
async def test_ca_cert_skipped(tmp_path: Path):
    # CA certs (the system trust bundle) are out of scope and must not flood
    # the report — only end-entity certs are flagged.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(priv, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding
    (tmp_path / "root-ca.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_malformed_file_skipped(tmp_path: Path):
    (tmp_path / "junk.pem").write_bytes(b"not a certificate at all")
    _write_cert(tmp_path / "good.pem", datetime(2036, 1, 1, tzinfo=UTC))
    found = await _run(tmp_path)
    # The junk file is silently skipped; the valid cert is still scanned.
    assert len(found) == 1


@pytest.mark.asyncio
async def test_non_cert_extension_ignored(tmp_path: Path):
    _write_cert(tmp_path / "c.txt", datetime(2036, 1, 1, tzinfo=UTC))
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path: Path):
    probe = FsCertExpiryHorizon(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is True


@pytest.mark.asyncio
async def test_applies_false_when_no_root(tmp_path: Path):
    probe = FsCertExpiryHorizon(roots=[tmp_path / "nope"])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is False


def test_default_roots():
    probe = FsCertExpiryHorizon()
    assert Path("/etc/ssl") in probe.roots
    assert Path("/etc/pki") in probe.roots


@pytest.mark.asyncio
async def test_overlapping_roots_dedupe(tmp_path: Path):
    # /etc/ssl and /etc/ssl/certs overlap in defaults; ensure a cert under a
    # nested overlapping root is not emitted twice.
    nested = tmp_path / "certs"
    nested.mkdir()
    _write_cert(nested / "c.pem", datetime(2036, 1, 1, tzinfo=UTC))
    found: list = []
    probe = FsCertExpiryHorizon(roots=[tmp_path, nested])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
