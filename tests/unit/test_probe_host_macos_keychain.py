"""Tests for host.macos.keychain (macOS system trust store inventory).

The probe is fed an injected PEM bundle via `security_pem=` so it runs on
Linux CI with no macOS `security` CLI. We build self-signed roots in-test
with the `cryptography` lib: one RSA-1024 (broken now → SANGAT_TINGGI) and
one RSA-2048 (classical, quantum-vulnerable → TINGGI). The SHA-1/MD5
signature path is asserted directly (this build refuses to sign with SHA-1).
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_macos_keychain import HostMacosKeychain


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _self_signed(cn: str, key_size: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


async def _run(security_pem: str) -> list:
    found: list = []
    probe = HostMacosKeychain(security_pem=security_pem)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_rsa1024_is_sangat_tinggi():
    # RSA-1024 is broken now regardless of the signature hash. (This
    # cryptography build refuses to *sign* with SHA-1, so we drive the weak
    # tier via the sub-2048 modulus; the SHA-1 sig path is covered by
    # test_sha1_signature_classifies_sangat_tinggi below.)
    pem = _self_signed("weak-root", 1024)
    found = await _run(pem)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.algorithm == "keychain-root/RSA-SHA256"
    assert f.evidence["key"] == "RSA-1024"
    assert "weak-root" in f.evidence["subject"]


def test_sha1_signature_classifies_sangat_tinggi():
    # A SHA-1 / MD5 signature is broken-now even on an otherwise strong key.
    assert (
        HostMacosKeychain._classify_root("RSA-SHA1", "RSA-2048")
        is Classification.SANGAT_TINGGI
    )
    assert (
        HostMacosKeychain._classify_root("RSA-MD5", "RSA-2048")
        is Classification.SANGAT_TINGGI
    )


@pytest.mark.asyncio
async def test_rsa2048_sha256_is_tinggi():
    pem = _self_signed("modern-root", 2048)
    found = await _run(pem)
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH
    assert f.algorithm == "keychain-root/RSA-SHA256"
    assert f.evidence["key"] == "RSA-2048"


@pytest.mark.asyncio
async def test_bundle_emits_one_per_root():
    bundle = (
        _self_signed("weak-root", 1024)
        + _self_signed("modern-root", 2048)
    )
    found = await _run(bundle)
    classes = sorted(f.classification for f in found)
    assert classes == sorted(
        [Classification.SANGAT_TINGGI, Classification.TINGGI]
    )


@pytest.mark.asyncio
async def test_duplicate_root_is_deduped():
    one = _self_signed("dup-root", 2048)
    found = await _run(one + one)
    assert len(found) == 1


@pytest.mark.asyncio
async def test_empty_pem_no_findings():
    found = await _run("")
    assert found == []


@pytest.mark.asyncio
async def test_garbage_pem_no_crash():
    garbage = (
        "-----BEGIN CERTIFICATE-----\n"
        "bm90IGEgcmVhbCBjZXJ0aWZpY2F0ZQ==\n"
        "-----END CERTIFICATE-----\n"
        "totally not pem at all\n"
    )
    found = await _run(garbage)
    assert found == []


@pytest.mark.asyncio
async def test_applies_true_when_pem_injected():
    probe = HostMacosKeychain(security_pem="")
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_false_off_darwin_without_pem():
    # On Linux CI with no injected pem, the probe must not claim to apply.
    probe = HostMacosKeychain(security_cmd="/no/such/security")
    assert await probe.applies(_ctx()) is False
