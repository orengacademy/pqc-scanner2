"""Tests for host.openssl.version (`openssl version -a` PQC capability tier)."""
import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_version import HostOpenSSLVersion


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(version_output: str) -> list:
    found: list = []
    probe = HostOpenSSLVersion(openssl="/no/such/openssl", version_output=version_output)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_openssl_35_native_pqc():
    found = await _run("OpenSSL 3.5.0 8 Apr 2025\nbuilt on: ...\n")
    assert len(found) == 1
    assert found[0].classification is Classification.PQC_READY
    assert found[0].severity is Severity.INFO
    assert found[0].algorithm == "OpenSSL/3.5.0"


@pytest.mark.asyncio
async def test_openssl_30_needs_oqs_provider():
    found = await _run("OpenSSL 3.0.13 30 Jan 2024\n")
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_openssl_111_eol_high():
    found = await _run("OpenSSL 1.1.1w 11 Sep 2023\n")
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_libressl_is_medium():
    found = await _run("LibreSSL 3.8.2\n")
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].algorithm == "LibreSSL/3.8.2"


@pytest.mark.asyncio
async def test_unparseable_emits_nothing():
    assert await _run("") == []


@pytest.mark.asyncio
async def test_applies():
    assert await HostOpenSSLVersion(
        openssl="/no/such/openssl", version_output="OpenSSL 3.5.0\n"
    ).applies(_ctx()) is True
    assert await HostOpenSSLVersion(openssl="/no/such/openssl").applies(_ctx()) is False
