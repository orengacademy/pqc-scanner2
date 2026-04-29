import shutil
import subprocess
from pathlib import Path

import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_x509 import FsCertX509


def _make_self_signed_cert(d: Path, key_size: int) -> Path:
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    key = d / "k.pem"
    cert = d / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", f"rsa:{key_size}", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=test"],
        check=True, capture_output=True,
    )
    return cert


@pytest.mark.asyncio
async def test_flags_rsa_1024(tmp_path: Path):
    _make_self_signed_cert(tmp_path, 1024)
    found: list = []
    probe = FsCertX509(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_flags_rsa_2048_as_sangat_tinggi(tmp_path: Path):
    # Per spec Appendix B: RSA <3072 -> Sangat Tinggi (matches updated alg test).
    _make_self_signed_cert(tmp_path, 2048)
    found: list = []
    probe = FsCertX509(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)
