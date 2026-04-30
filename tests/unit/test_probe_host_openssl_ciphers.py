import shutil

import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_ciphers import HostOpenSSLCiphers


@pytest.mark.asyncio
async def test_emits_findings_when_openssl_present():
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    found: list = []
    probe = HostOpenSSLCiphers()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    # OpenSSL `ciphers ALL` typically lists at least one Tinggi/Sangat-Tinggi
    # entry (RSA-key-exchange, AES-128, etc.), so we expect non-zero findings.
    assert len(found) > 0
    assert all(
        f.classification in {Classification.SANGAT_TINGGI, Classification.TINGGI}
        for f in found
    )


@pytest.mark.asyncio
async def test_skips_when_openssl_absent():
    probe = HostOpenSSLCiphers(openssl="/no/such/openssl")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await probe.applies(ctx)
