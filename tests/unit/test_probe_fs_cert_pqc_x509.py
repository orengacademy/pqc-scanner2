"""Tests for fs.cert.pqc_x509 — PQC X.509 cert recognition.

`cryptography` can't sign with ML-DSA/SLH-DSA, so real PQC certs can't be built
in-process. We monkeypatch `_load_cert` to return a stub cert carrying the
signature-algorithm OID under test — which is exactly what the probe reads —
proving recognition across the full standardized PQC OID surface (pure,
pre-hash, composite, Falcon) and that classical certs are ignored.
"""
import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes import fs_cert_pqc_x509 as m
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_pqc_x509 import FsCertPqcX509


class _FakeOID:
    def __init__(self, dotted: str) -> None:
        self.dotted_string = dotted


class _FakeName:
    def rfc4514_string(self) -> str:
        return "CN=pqc-test"


class _FakeCert:
    def __init__(self, sig_oid: str) -> None:
        self.signature_algorithm_oid = _FakeOID(sig_oid)
        self.subject = _FakeName()

    def public_bytes(self, encoding) -> bytes:
        return b"-----BEGIN CERTIFICATE-----\nMIIB...stub...\n"


def _run(tmp_path, sig_oid: str, monkeypatch):
    (tmp_path / "cert.der").write_bytes(b"stub")
    monkeypatch.setattr(m, "_load_cert", lambda path: _FakeCert(sig_oid))
    probe = FsCertPqcX509()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set(),
                      scan_paths=[tmp_path])
    out: list = []
    import asyncio
    asyncio.run(probe.run(ctx, out.append))
    return out


def test_metadata():
    p = FsCertPqcX509()
    assert p.id == "fs.cert.pqc_x509"
    assert p.family is ProbeFamily.FILESYSTEM


@pytest.mark.parametrize(("oid", "name"), [
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),            # pure
    ("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"),    # pure
    ("2.16.840.1.101.3.4.3.32", "HashML-DSA-44"),        # pre-hash (NEW recall)
    ("2.16.840.1.101.3.4.3.40", "HashSLH-DSA-SHA2-256f"),  # pre-hash (NEW recall)
    ("1.3.6.1.5.5.7.6.41", "ML-DSA-65+RSA3072-PSS"),     # composite (NEW recall)
    ("1.3.9999.3.6", "Falcon-512"),                      # Falcon
])
def test_recognizes_pqc_cert(tmp_path, monkeypatch, oid, name):
    out = _run(tmp_path, oid, monkeypatch)
    assert len(out) == 1
    f = out[0]
    assert f.classification is Classification.PQC_READY
    assert f.algorithm == name
    assert f.evidence["signature_algorithm_oid"] == oid
    assert f.evidence["signature_algorithm"] == name


@pytest.mark.parametrize("oid", [
    "1.2.840.113549.1.1.11",   # RSA-SHA256
    "1.2.840.10045.4.3.2",     # ECDSA-SHA256
    "1.3.101.112",             # Ed25519
])
def test_ignores_classical_cert(tmp_path, monkeypatch, oid):
    assert _run(tmp_path, oid, monkeypatch) == []


@pytest.mark.asyncio
async def test_applies_needs_scan_paths():
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await FsCertPqcX509().applies(ctx) is False
