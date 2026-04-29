from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_config import HostOpenSSLConfig


@pytest.mark.asyncio
async def test_detects_legacy_provider(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "\n[provider_sect]\n"
        "default = default_sect\n"
        "legacy = legacy_sect\n"
        "\n[default_sect]\n"
        "activate = 1\n"
        "\n[legacy_sect]\n"
        "activate = 1\n"
    )
    found: list = []
    probe = HostOpenSSLConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any("legacy" in f.title.lower() for f in found)


@pytest.mark.asyncio
async def test_no_findings_for_modern_config(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text("[default_sect]\nactivate = 1\n")
    found: list = []
    probe = HostOpenSSLConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert not found
