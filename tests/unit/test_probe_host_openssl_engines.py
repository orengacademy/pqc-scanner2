import shutil

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_engines import HostOpenSSLEngines


@pytest.mark.asyncio
async def test_runs_without_error_when_openssl_present():
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    found: list = []
    probe = HostOpenSSLEngines()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    # Output may or may not contain 'legacy' depending on host; we only assert
    # that the probe runs cleanly. If it does fire, the finding must be marked
    # as a high-severity legacy detection.
    if found:
        assert any("legacy" in f.title.lower() for f in found)


@pytest.mark.asyncio
async def test_skips_when_openssl_absent():
    probe = HostOpenSSLEngines(openssl="/no/such/openssl")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await probe.applies(ctx)
