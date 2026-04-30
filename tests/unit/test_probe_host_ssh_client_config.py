from pathlib import Path

import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_ssh_client_config import HostSshClientConfig


@pytest.mark.asyncio
async def test_flags_md5_mac_in_client_config(tmp_path: Path):
    cfg = tmp_path / "ssh_config"
    cfg.write_text(
        "Host *\n"
        "    Ciphers aes256-gcm@openssh.com\n"
        "    KexAlgorithms curve25519-sha256\n"
        "    MACs hmac-md5,hmac-sha2-256\n"
    )
    found: list = []
    probe = HostSshClientConfig(config_paths=[cfg])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("hmac-md5" in t for t in titles)
    md5 = [f for f in found if "hmac-md5" in f.title]
    assert any(f.classification is Classification.SANGAT_TINGGI for f in md5)
