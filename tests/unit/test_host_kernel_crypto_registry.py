from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_kernel_crypto_registry import HostKernelCryptoRegistry

# Hand-written /proc/crypto fixture: weak (md5, des3_ede, ecb(des)) and
# modern (aes, sha256, xts) blocks separated by blank lines.
_PROC_CRYPTO = """name         : md5
driver       : md5-generic
module       : kernel
priority     : 0
type         : shash
blocksize    : 64
digestsize   : 16

name         : des3_ede
driver       : des3_ede-generic
module       : des_generic
priority     : 100
type         : cipher
blocksize    : 8

name         : ecb(des)
driver       : ecb-des-generic
module       : kernel
priority     : 100
type         : skcipher

name         : aes
driver       : aes-generic
module       : kernel
priority     : 100
type         : cipher
blocksize    : 16

name         : sha256
driver       : sha256-generic
module       : kernel
priority     : 100
type         : shash
digestsize   : 32

name         : xts(aes)
driver       : xts-aes-aesni
module       : kernel
priority     : 401
type         : skcipher
"""


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


@pytest.mark.asyncio
async def test_flags_only_weak_algorithms(tmp_path: Path):
    proc = tmp_path / "crypto"
    proc.write_text(_PROC_CRYPTO)
    found: list = []
    probe = HostKernelCryptoRegistry(proc_crypto_path=proc)
    await probe.run(_ctx(), emit=lambda f: found.append(f))

    algs = {f.algorithm for f in found}
    assert algs == {"md5", "des3_ede", "ecb(des)"}
    # Modern algorithms are never flagged.
    assert "aes" not in algs
    assert "sha256" not in algs
    assert "xts(aes)" not in algs


@pytest.mark.asyncio
async def test_weak_findings_are_tinggi_high(tmp_path: Path):
    proc = tmp_path / "crypto"
    proc.write_text(_PROC_CRYPTO)
    found: list = []
    probe = HostKernelCryptoRegistry(proc_crypto_path=proc)
    await probe.run(_ctx(), emit=lambda f: found.append(f))

    assert found
    for f in found:
        assert f.classification is Classification.TINGGI
        assert f.severity is Severity.HIGH
        assert f.probe_id == "host.kernel.crypto_registry"


@pytest.mark.asyncio
async def test_one_finding_per_distinct_weak_name(tmp_path: Path):
    proc = tmp_path / "crypto"
    proc.write_text(
        "name : md5\ntype : shash\n\n"
        "name : md5\ntype : shash\n\n"
        "name : des\ntype : cipher\n"
    )
    found: list = []
    probe = HostKernelCryptoRegistry(proc_crypto_path=proc)
    await probe.run(_ctx(), emit=lambda f: found.append(f))

    algs = [f.algorithm for f in found]
    assert sorted(algs) == ["des", "md5"]


@pytest.mark.asyncio
async def test_absent_file_no_findings(tmp_path: Path):
    proc = tmp_path / "does_not_exist"
    found: list = []
    probe = HostKernelCryptoRegistry(proc_crypto_path=proc)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert not found
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_file_present(tmp_path: Path):
    proc = tmp_path / "crypto"
    proc.write_text("name : aes\ntype : cipher\n")
    probe = HostKernelCryptoRegistry(proc_crypto_path=proc)
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_modern_only_yields_nothing(tmp_path: Path):
    proc = tmp_path / "crypto"
    proc.write_text(
        "name : aes\ntype : cipher\n\n"
        "name : sha512\ntype : shash\n\n"
        "name : gcm(aes)\ntype : aead\n"
    )
    found: list = []
    probe = HostKernelCryptoRegistry(proc_crypto_path=proc)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert not found
