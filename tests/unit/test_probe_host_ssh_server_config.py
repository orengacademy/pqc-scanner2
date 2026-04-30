from pathlib import Path

import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_ssh_server_config import HostSshServerConfig


@pytest.mark.asyncio
async def test_flags_sha1_kex_and_md5_mac(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(
        "Port 22\n"
        "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,curve25519-sha256\n"
        "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n"
        "MACs hmac-md5,hmac-sha2-256\n"
    )
    found: list = []
    probe = HostSshServerConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))

    titles = [f.title for f in found]
    assert any("group1-sha1" in t for t in titles)
    assert any("hmac-md5" in t for t in titles)

    md5_findings = [f for f in found if "hmac-md5" in f.title]
    assert any(f.classification is Classification.SANGAT_TINGGI for f in md5_findings)


@pytest.mark.asyncio
async def test_skips_comments_and_blank_lines(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(
        "# Sample sshd_config\n"
        "\n"
        "  # KexAlgorithms diffie-hellman-group1-sha1  <- commented out\n"
        "Port 22\n"
    )
    found: list = []
    probe = HostSshServerConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert found == []
