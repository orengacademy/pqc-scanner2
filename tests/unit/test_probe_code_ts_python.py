from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_ts_python import CodeTsPython


@pytest.mark.asyncio
async def test_flags_md5_usage(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("import hashlib\n\nh = hashlib.md5(b'abc').hexdigest()\n")
    found = []
    probe = CodeTsPython(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda x: found.append(x))
    assert any("md5" in fnd.title.lower() for fnd in found)
