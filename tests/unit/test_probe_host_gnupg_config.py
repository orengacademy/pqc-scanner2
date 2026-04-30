from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_gnupg_config import HostGnupgConfig


@pytest.mark.asyncio
async def test_flags_md5_in_personal_digest(tmp_path: Path):
    cfg = tmp_path / "gpg.conf"
    cfg.write_text(
        "personal-cipher-preferences AES256 AES192 AES\n"
        "personal-digest-preferences SHA512 SHA384 SHA1 MD5\n"
    )
    found: list = []
    probe = HostGnupgConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("MD5" in t for t in titles)
    assert any("SHA1" in t for t in titles)


@pytest.mark.asyncio
async def test_no_findings_for_modern_only(tmp_path: Path):
    cfg = tmp_path / "gpg.conf"
    cfg.write_text(
        "personal-cipher-preferences AES256\n"
        "personal-digest-preferences SHA512 SHA384\n"
    )
    found: list = []
    probe = HostGnupgConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert found == []
