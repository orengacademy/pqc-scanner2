"""Tests for Plan G batch 3 — hardware crypto probes (TPM, PKCS#11, smartcards)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.hw_pkcs11_modules import HwPkcs11Modules
from pqcscan.probes.hw_smartcard_readers import HwSmartcardReaders
from pqcscan.probes.hw_tpm_algorithms import HwTpmAlgorithms


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (HwTpmAlgorithms,    "hw.tpm.algorithms"),
        (HwPkcs11Modules,    "hw.pkcs11.modules"),
        (HwSmartcardReaders, "hw.smartcard.readers"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.STORAGE
    assert any("hw" in tag for tag in p.framework_tags)


@pytest.mark.asyncio
async def test_tpm_flags_sha1_pcr_bank(tmp_path: Path):
    tpm = tmp_path / "tpm0"
    tpm.mkdir()
    (tpm / "tpm_version_major").write_text("2\n")
    (tpm / "active_pcr_banks").write_text("sha1 sha256\n")
    found: list = []
    p = HwTpmAlgorithms(sysfs_root=tmp_path)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "TPM-2.0" for f in found)
    sha1 = [f for f in found if f.algorithm == "TPM-PCR-SHA1"]
    assert sha1 and sha1[0].classification is Classification.TINGGI
    sha256 = [f for f in found if f.algorithm == "TPM-PCR-SHA256"]
    assert sha256 and sha256[0].classification is Classification.INFO


@pytest.mark.asyncio
async def test_tpm_flags_legacy_v1(tmp_path: Path):
    tpm = tmp_path / "tpm0"
    tpm.mkdir()
    (tpm / "tpm_version_major").write_text("1\n")
    found: list = []
    p = HwTpmAlgorithms(sysfs_root=tmp_path)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "TPM-1.2"
               and f.classification is Classification.TINGGI
               for f in found)


@pytest.mark.asyncio
async def test_tpm_no_sysfs_emits_nothing(tmp_path: Path):
    found: list = []
    p = HwTpmAlgorithms(sysfs_root=tmp_path / "does-not-exist")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert found == []


@pytest.mark.asyncio
async def test_pkcs11_modules_lists_providers(tmp_path: Path):
    (tmp_path / "softhsm.module").write_text(
        "module: /usr/lib/softhsm/libsofthsm2.so\npriority: 50\n"
    )
    found: list = []
    p = HwPkcs11Modules(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("libsofthsm2.so" in f.algorithm for f in found)
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_smartcard_flags_short_default_keylen(tmp_path: Path):
    cfg = tmp_path / "opensc.conf"
    cfg.write_text(
        "app default {\n"
        "  framework pkcs15 {\n"
        "    default_key_length = 1024;\n"
        "  };\n"
        "};\n"
    )
    found: list = []
    p = HwSmartcardReaders(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    short = [f for f in found if "1024" in f.algorithm]
    assert short and short[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_smartcard_3072_is_info(tmp_path: Path):
    cfg = tmp_path / "opensc.conf"
    cfg.write_text(
        "app default {\n"
        "  framework pkcs15 {\n"
        "    default_key_length = 3072;\n"
        "  };\n"
        "};\n"
    )
    found: list = []
    p = HwSmartcardReaders(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


def test_registry_includes_hw_probes():
    from pqcscan.probes._registry import default_registry
    reg = default_registry()
    ids = set(reg.ids())
    expected = {
        "hw.tpm.algorithms", "hw.pkcs11.modules", "hw.smartcard.readers",
    }
    assert expected <= ids
