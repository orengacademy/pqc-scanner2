from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_sshd import FsConfSshd


@pytest.mark.asyncio
async def test_scans_sshd_config_d_directory(tmp_path: Path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "00-legacy.conf").write_text(
        "KexAlgorithms diffie-hellman-group1-sha1\n"
    )
    (d / "10-modern.conf").write_text(
        "KexAlgorithms curve25519-sha256\n"
    )
    found: list = []
    probe = FsConfSshd(roots=[d])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("group1-sha1" in t for t in titles)
