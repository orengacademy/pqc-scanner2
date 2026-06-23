from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_revocation import FsCertRevocation


def _build_cert(
    *,
    key: object | None = None,
    ca: bool = False,
    ocsp_url: str | None = None,
    crl_url: str | None = None,
    must_staple: bool = False,
    extensions: list | None = None,
) -> x509.Certificate:
    priv = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    if ocsp_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
    if crl_url is not None:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
            critical=False,
        )
    if must_staple:
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )
    for ext, critical in extensions or []:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(priv, hashes.SHA256())


def _write(path: Path, cert: x509.Certificate, encoding: str = "pem") -> None:
    enc = Encoding.PEM if encoding == "pem" else Encoding.DER
    path.write_bytes(cert.public_bytes(enc))


async def _run(tmp_path: Path) -> list:
    found: list = []
    probe = FsCertRevocation(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_directoryname_crldp_no_crash_and_json_safe(tmp_path: Path):
    # A non-URI GeneralName (DirectoryName) in the CRLDP must NOT leak a
    # cryptography Name object into evidence (which would break JSON
    # serialization at DB persist). It is skipped -> no revocation path.
    import json
    dn = x509.DirectoryName(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crl-issuer")])
    )
    cert = _build_cert(extensions=[(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[dn], relative_name=None, reasons=None, crl_issuer=None
            )
        ]), False,
    )])
    _write(tmp_path / "dn.pem", cert)
    found = await _run(tmp_path)
    assert len(found) == 1
    json.dumps(found[0].evidence)  # must not raise
    assert found[0].evidence["crl_urls"] == []


@pytest.mark.asyncio
async def test_no_revocation_path_is_sederhana_med(tmp_path: Path):
    _write(tmp_path / "c.pem", _build_cert())
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.probe_id == "fs.cert.revocation"
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED
    assert "no revocation path" in f.title
    assert f.evidence["ocsp_urls"] == []
    assert f.evidence["crl_urls"] == []


@pytest.mark.asyncio
async def test_ocsp_url_emits_info(tmp_path: Path):
    _write(tmp_path / "c.pem", _build_cert(ocsp_url="http://ocsp.example.com"))
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.INFO
    assert f.severity is Severity.INFO
    assert f.evidence["ocsp_urls"] == ["http://ocsp.example.com"]
    assert f.evidence["crl_urls"] == []


@pytest.mark.asyncio
async def test_crl_url_emits_info(tmp_path: Path):
    _write(tmp_path / "c.pem", _build_cert(crl_url="http://crl.example.com/a.crl"))
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.INFO
    assert f.evidence["crl_urls"] == ["http://crl.example.com/a.crl"]
    assert f.evidence["ocsp_urls"] == []


@pytest.mark.asyncio
async def test_must_staple_recorded(tmp_path: Path):
    cert = _build_cert(ocsp_url="http://ocsp.example.com", must_staple=True)
    _write(tmp_path / "c.pem", cert)
    found = await _run(tmp_path)
    assert found[0].evidence["must_staple"] is True


@pytest.mark.asyncio
async def test_must_staple_false_by_default(tmp_path: Path):
    _write(tmp_path / "c.pem", _build_cert(ocsp_url="http://ocsp.example.com"))
    found = await _run(tmp_path)
    assert found[0].evidence["must_staple"] is False


@pytest.mark.asyncio
async def test_sct_present_recorded(tmp_path: Path):
    # Build a precert poison cert just to confirm absence reporting works;
    # embedding real SCTs requires a signer, so we assert the default False
    # path and that the key is present in evidence.
    _write(tmp_path / "c.pem", _build_cert(crl_url="http://crl.example.com/a.crl"))
    found = await _run(tmp_path)
    assert found[0].evidence["sct_present"] is False


@pytest.mark.asyncio
async def test_ca_cert_skipped(tmp_path: Path):
    _write(tmp_path / "root-ca.pem", _build_cert(ca=True))
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_ec_key_is_classical(tmp_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    _write(tmp_path / "c.pem", _build_cert(key=key))
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm.startswith("ECDSA-")
    assert found[0].classification is Classification.SEDERHANA


@pytest.mark.asyncio
async def test_der_encoded_cert_parsed(tmp_path: Path):
    _write(tmp_path / "c.cer", _build_cert(), encoding="der")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA


@pytest.mark.asyncio
async def test_evidence_records_path_and_subject(tmp_path: Path):
    cpath = tmp_path / "c.pem"
    _write(cpath, _build_cert())
    found = await _run(tmp_path)
    ev = found[0].evidence
    assert ev["path"] == str(cpath)
    assert "test" in ev["subject"]


@pytest.mark.asyncio
async def test_malformed_file_skipped(tmp_path: Path):
    (tmp_path / "junk.pem").write_bytes(b"not a certificate at all")
    _write(tmp_path / "good.pem", _build_cert())
    found = await _run(tmp_path)
    assert len(found) == 1


@pytest.mark.asyncio
async def test_oversize_file_skipped(tmp_path: Path):
    big = tmp_path / "big.pem"
    big.write_bytes(b"x" * (2 * 1024 * 1024))
    _write(tmp_path / "good.pem", _build_cert())
    found = await _run(tmp_path)
    assert len(found) == 1


@pytest.mark.asyncio
async def test_non_cert_extension_ignored(tmp_path: Path):
    _write(tmp_path / "c.txt", _build_cert())
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path: Path):
    probe = FsCertRevocation(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is True


@pytest.mark.asyncio
async def test_applies_false_when_no_root(tmp_path: Path):
    probe = FsCertRevocation(roots=[tmp_path / "nope"])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is False


def test_default_roots():
    probe = FsCertRevocation()
    assert Path("/etc/ssl") in probe.roots
    assert Path("/etc/pki") in probe.roots


@pytest.mark.asyncio
async def test_overlapping_roots_dedupe(tmp_path: Path):
    nested = tmp_path / "certs"
    nested.mkdir()
    _write(nested / "c.pem", _build_cert())
    found: list = []
    probe = FsCertRevocation(roots=[tmp_path, nested])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
