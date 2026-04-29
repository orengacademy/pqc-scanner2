from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.sbom_os_dpkg import SbomOsDpkg


@pytest.mark.asyncio
async def test_sbom_dpkg_emits_packages(tmp_path: Path):
    status = tmp_path / "status"
    status.write_text(
        "Package: openssl\nVersion: 3.0.2-1ubuntu1.10\n"
        "Status: install ok installed\n\n"
        "Package: libssl3\nVersion: 3.0.2-1ubuntu1.10\n"
        "Status: install ok installed\n"
    )
    found = []
    probe = SbomOsDpkg(status_path=status)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("openssl" in t for t in titles)
    assert any("libssl3" in t for t in titles)
