from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_csr import FsCertCsr

_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _write_csr(path: Path, key, hash_alg, *, der: bool = False) -> Path:
    builder = x509.CertificateSigningRequestBuilder().subject_name(_SUBJECT)
    csr = builder.sign(key, hash_alg)
    enc = serialization.Encoding.DER if der else serialization.Encoding.PEM
    path.write_bytes(csr.public_bytes(enc))
    return path


async def _run(root: Path) -> list:
    found: list = []
    probe = FsCertCsr(roots=[root])
    await probe.run(_ctx(), emit=found.append)
    return found


def test_defaults_and_tags():
    probe = FsCertCsr()
    assert probe.id == "fs.cert.csr"
    assert probe.framework_tags == ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")
    assert probe.roots == [Path("/etc/ssl"), Path("/etc/pki")]


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path: Path):
    probe = FsCertCsr(roots=[tmp_path])
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_false_when_no_root(tmp_path: Path):
    probe = FsCertCsr(roots=[tmp_path / "nope"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_rsa_1024_flagged_sangat_tinggi(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _write_csr(tmp_path / "a.csr", key, hashes.SHA256())
    found = await _run(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.probe_id == "fs.cert.csr"


@pytest.mark.asyncio
async def test_rsa_3072_modern_classical_med(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _write_csr(tmp_path / "a.csr", key, hashes.SHA256())
    found = await _run(tmp_path)
    assert len(found) == 1
    # RSA-3072 -> TINGGI/HIGH per alg.classify; SHA256 -> SEDERHANA. Worst wins.
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_sha1_signature_flagged_high(tmp_path: Path, monkeypatch):
    # This OpenSSL build refuses to *sign* with SHA1, so build a valid CSR and
    # patch load_*_x509_csr to report a SHA1 signature hash on load — exercising
    # the probe's "SHA1 dominates" classification path deterministically.
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _write_csr(tmp_path / "a.csr", key, hashes.SHA256())

    import pqcscan.probes.fs_cert_csr as mod

    real_load = x509.load_pem_x509_csr

    class _Sha1Csr:
        def __init__(self, inner):
            self._inner = inner
            self.signature_hash_algorithm = hashes.SHA1()

        def public_key(self):
            return self._inner.public_key()

        @property
        def subject(self):
            return self._inner.subject

    monkeypatch.setattr(mod.x509, "load_pem_x509_csr", lambda d: _Sha1Csr(real_load(d)))

    found = await _run(tmp_path)
    assert len(found) == 1
    # SHA1 -> SANGAT_TINGGI dominates over RSA-3072 TINGGI.
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT
    assert found[0].evidence["signature_hash"] == "SHA1"


@pytest.mark.asyncio
async def test_ecdsa_high(tmp_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    _write_csr(tmp_path / "a.csr", key, hashes.SHA256())
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].evidence["public_key"].startswith("ECDSA-")


@pytest.mark.asyncio
async def test_ed25519_no_hash(tmp_path: Path):
    key = ed25519.Ed25519PrivateKey.generate()
    builder = x509.CertificateSigningRequestBuilder().subject_name(_SUBJECT)
    csr = builder.sign(key, None)
    (tmp_path / "a.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].evidence["signature_hash"] is None
    assert found[0].evidence["public_key"] == "Ed25519"


@pytest.mark.asyncio
async def test_dsa_flagged(tmp_path: Path):
    key = dsa.generate_private_key(key_size=1024)
    _write_csr(tmp_path / "a.csr", key, hashes.SHA256())
    found = await _run(tmp_path)
    assert len(found) == 1
    # DSA -> SANGAT_TINGGI.
    assert found[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_der_encoding_and_req_ext(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _write_csr(tmp_path / "a.req", key, hashes.SHA256(), der=True)
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_malformed_file_skipped(tmp_path: Path):
    (tmp_path / "bad.csr").write_bytes(b"not a real csr at all")
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _write_csr(tmp_path / "good.csr", key, hashes.SHA256())
    found = await _run(tmp_path)
    # Malformed file is skipped, scan continues for the good one.
    assert len(found) == 1


@pytest.mark.asyncio
async def test_non_csr_extension_ignored(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _write_csr(tmp_path / "a.pem", key, hashes.SHA256())
    found = await _run(tmp_path)
    assert found == []
