from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_nginx import FsConfNginx


@pytest.mark.asyncio
async def test_flags_tlsv1_in_ssl_protocols(tmp_path: Path):
    cfg = tmp_path / "site.conf"
    cfg.write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n"
        "  ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n"
    )
    found: list = []
    probe = FsConfNginx(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("TLSv1" in t and "TLSv1.1" not in t for t in titles)
    assert any("TLSv1.1" in t for t in titles)


@pytest.mark.asyncio
async def test_no_findings_for_modern_protocols_only(tmp_path: Path):
    cfg = tmp_path / "site.conf"
    cfg.write_text(
        "server {\n"
        "  ssl_protocols TLSv1.2 TLSv1.3;\n"
        "}\n"
    )
    found: list = []
    probe = FsConfNginx(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    proto_titles = [f.title for f in found if "ssl_protocols" in f.title]
    assert proto_titles == []
