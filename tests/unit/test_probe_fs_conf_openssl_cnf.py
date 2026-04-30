from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_openssl_cnf import FsConfOpensslCnf


@pytest.mark.asyncio
async def test_flags_legacy_provider_in_arbitrary_path(tmp_path: Path):
    cnf = tmp_path / "alt-openssl.cnf"
    cnf.write_text(
        "[provider_sect]\n"
        "default = default_sect\n"
        "legacy = legacy_sect\n"
        "\n[default_sect]\n"
        "activate = 1\n"
        "\n[legacy_sect]\n"
        "activate = 1\n"
    )
    found: list = []
    probe = FsConfOpensslCnf(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any("legacy" in f.title.lower() for f in found)


@pytest.mark.asyncio
async def test_no_findings_when_legacy_disabled(tmp_path: Path):
    cnf = tmp_path / "alt-openssl.cnf"
    cnf.write_text(
        "[provider_sect]\n"
        "default = default_sect\n"
        "\n[default_sect]\n"
        "activate = 1\n"
    )
    found: list = []
    probe = FsConfOpensslCnf(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert found == []
