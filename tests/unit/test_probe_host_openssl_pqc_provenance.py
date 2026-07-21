"""Tests for host.openssl.pqc_provenance — native vs oqs-provider vs none.

The probe synthesizes `openssl version` + `openssl list -providers` into one
provenance verdict. Both are injected via seams, so no real openssl is needed.
"""
import asyncio

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_pqc_provenance import HostOpenSSLPqcProvenance

_NO_OQS = "Providers:\n  default\n    name: OpenSSL Default Provider\n    status: active\n"
_WITH_OQS = (
    "Providers:\n  default\n    name: OpenSSL Default Provider\n"
    "  oqsprovider\n    name: OpenSSL OQS Provider\n    status: active\n"
)


def _run(version: str, providers: str):
    probe = HostOpenSSLPqcProvenance(version_output=version, providers_output=providers)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    out: list = []
    asyncio.run(probe.run(ctx, out.append))
    return out


def test_metadata():
    p = HostOpenSSLPqcProvenance()
    assert p.id == "host.openssl.pqc_provenance"
    assert p.family is ProbeFamily.HOST


def test_registered():
    from pqcscan.probes._registry import default_registry
    assert "host.openssl.pqc_provenance" in default_registry().ids()


def test_native_openssl_35():
    (f,) = _run("OpenSSL 3.5.0 1 Apr 2025", _NO_OQS)
    assert f.evidence["pqc_provenance"] == "native"
    assert f.evidence["native_pqc"] is True
    assert f.classification is Classification.PQC_READY


def test_oqs_provider_addon_on_33_is_distinct_from_native():
    # The whole point: OpenSSL 3.3 with oqs-provider loaded IS PQC-capable, but
    # via the add-on — not native. The version probe alone can't tell these apart.
    (f,) = _run("OpenSSL 3.3.1 4 Jun 2024", _WITH_OQS)
    assert f.evidence["pqc_provenance"] == "oqs-provider"
    assert f.evidence["native_pqc"] is False
    assert f.evidence["oqs_provider_loaded"] is True
    assert f.classification is Classification.PQC_READY  # still PQC-capable
    assert "add-on" in f.title.lower()


def test_no_pqc_on_33_without_provider():
    (f,) = _run("OpenSSL 3.3.1 4 Jun 2024", _NO_OQS)
    assert f.evidence["pqc_provenance"] == "none"
    assert f.classification is Classification.SEDERHANA


def test_eol_openssl_is_high():
    (f,) = _run("OpenSSL 1.1.1w 11 Sep 2023", _NO_OQS)
    assert f.evidence["pqc_provenance"] == "none"
    assert f.classification is Classification.TINGGI


def test_redundant_oqs_on_35_stays_native():
    (f,) = _run("OpenSSL 3.5.0 1 Apr 2025", _WITH_OQS)
    assert f.evidence["pqc_provenance"] == "native"
    assert "redundant" in f.title.lower()


def test_non_openssl_stack():
    (f,) = _run("LibreSSL 3.8.2", _NO_OQS)
    assert f.evidence["pqc_provenance"] == "none"
    assert f.evidence["library"] == "LibreSSL"


@pytest.mark.asyncio
async def test_no_openssl_binary_skips_cleanly():
    # No seams, no openssl on PATH -> applies() False, run() emits nothing.
    probe = HostOpenSSLPqcProvenance(openssl_bin="definitely-not-a-real-binary-xyz")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await probe.applies(ctx) is False
    out: list = []
    await probe.run(ctx, out.append)
    assert out == []
