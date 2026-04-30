"""Smoke tests for storage.{luks,bitlocker,zfs,dmcrypt,fscrypt}."""
import sys
from pathlib import Path

import pytest

from pqcscan.core.types import Capability, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.storage_bitlocker import StorageBitlocker
from pqcscan.probes.storage_dmcrypt import StorageDmcrypt
from pqcscan.probes.storage_fscrypt import StorageFscrypt
from pqcscan.probes.storage_luks_headers import StorageLuksHeaders
from pqcscan.probes.storage_zfs_encryption import StorageZfsEncryption


@pytest.mark.parametrize(
    "cls,probe_id,family,requires_root",
    [
        (StorageLuksHeaders, "storage.luks.headers", ProbeFamily.STORAGE, True),
        (StorageBitlocker,   "storage.bitlocker",    ProbeFamily.STORAGE, True),
        (StorageZfsEncryption, "storage.zfs.encryption", ProbeFamily.STORAGE, False),
        (StorageDmcrypt,     "storage.dmcrypt",      ProbeFamily.STORAGE, True),
        (StorageFscrypt,     "storage.fscrypt",      ProbeFamily.STORAGE, False),
    ],
)
def test_metadata(cls, probe_id, family, requires_root):
    p = cls()
    assert p.id == probe_id
    assert p.family is family
    if requires_root:
        assert Capability.ROOT in p.requires


@pytest.mark.asyncio
async def test_luks_does_not_apply_in_user_mode():
    probe = StorageLuksHeaders()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await probe.applies(ctx)


@pytest.mark.asyncio
async def test_bitlocker_does_not_apply_on_linux():
    if sys.platform == "win32":
        pytest.skip("non-Windows guard test")
    probe = StorageBitlocker()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await probe.applies(ctx)


@pytest.mark.asyncio
async def test_fscrypt_emits_finding_when_cmdline_matches(tmp_path: Path):
    cmdline = tmp_path / "cmdline"
    cmdline.write_text("BOOT_IMAGE=/vmlinuz fscrypt=enabled root=/dev/sda1 ro\n")
    found: list = []
    probe = StorageFscrypt(cmdline_path=cmdline)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "AES-256-XTS" for f in found)


@pytest.mark.asyncio
async def test_fscrypt_no_finding_when_cmdline_clean(tmp_path: Path):
    cmdline = tmp_path / "cmdline"
    cmdline.write_text("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro\n")
    found: list = []
    probe = StorageFscrypt(cmdline_path=cmdline)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    # If fscrypt binary is on PATH the probe still fires from that detection
    # vector; otherwise zero. Either is acceptable.
    if not found:
        return
    # If fired, must be the AES-256-XTS finding from the binary-detection path.
    assert all(f.algorithm == "AES-256-XTS" for f in found)


@pytest.mark.asyncio
async def test_zfs_does_not_apply_when_zfs_absent():
    if sys.platform == "linux":
        # Most CI runners lack zfs; assert applies() = False then.
        probe = StorageZfsEncryption(zfs_bin="/no/such/zfs")
        ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
        assert not await probe.applies(ctx)


@pytest.mark.asyncio
async def test_dmcrypt_does_not_apply_in_user_mode():
    probe = StorageDmcrypt()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await probe.applies(ctx)
