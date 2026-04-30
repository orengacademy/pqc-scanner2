from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_apache import FsConfApache


@pytest.mark.asyncio
async def test_flags_sslv3_in_ssl_protocol(tmp_path: Path):
    cfg = tmp_path / "ssl.conf"
    cfg.write_text(
        "<VirtualHost *:443>\n"
        "  SSLEngine on\n"
        "  SSLProtocol +SSLv3 +TLSv1 +TLSv1.2\n"
        "</VirtualHost>\n"
    )
    found: list = []
    probe = FsConfApache(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("SSLv3" in t for t in titles)
    assert any("TLSv1" in t and "TLSv1.2" not in t for t in titles)
