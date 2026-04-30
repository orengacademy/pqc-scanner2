import shutil
import subprocess
from pathlib import Path

import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_privkey import FsCertPrivkey


def _make_rsa_key(d: Path, key_size: int) -> Path:
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    key = d / "k.key"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(key),
         "-pkeyopt", f"rsa_keygen_bits:{key_size}"],
        check=True, capture_output=True,
    )
    return key


@pytest.mark.asyncio
async def test_flags_rsa_1024_privkey(tmp_path: Path):
    _make_rsa_key(tmp_path, 1024)
    found: list = []
    probe = FsCertPrivkey(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_flags_rsa_2048_privkey_as_sangat_tinggi(tmp_path: Path):
    _make_rsa_key(tmp_path, 2048)
    found: list = []
    probe = FsCertPrivkey(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)
