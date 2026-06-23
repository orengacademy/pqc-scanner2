"""Tests for host.tpm.sealed_keys (TPM-sealed volume-key bindings)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_tpm_sealed_keys import HostTpmSealedKeys


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(crypttab: Path, clevis_dir: Path) -> list:
    found: list = []
    probe = HostTpmSealedKeys(paths=[crypttab, clevis_dir])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_tpm2_device_option_flags_mapping(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text("luks-root /dev/sda2 none tpm2-device=auto,luks\n")
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert len(found) == 1
    f = found[0]
    assert f.algorithm == "TPM-sealed"
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED
    assert f.evidence["volume"] == "luks-root"
    assert "tpm2-device=auto" in f.evidence["line"]


@pytest.mark.asyncio
async def test_tpm2_keyscript_flags_mapping(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text(
        "vault /dev/sdb1 none luks,keyscript=/usr/lib/tpm2-key-unseal\n"
    )
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert len(found) == 1
    assert found[0].evidence["volume"] == "vault"


@pytest.mark.asyncio
async def test_systemd_cryptenroll_tpm2_token_flags(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text("data /dev/sdc1 none luks,tpm2\n")
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert len(found) == 1
    assert found[0].evidence["volume"] == "data"


@pytest.mark.asyncio
async def test_clevis_binding_file_flags(tmp_path: Path):
    crypttab = tmp_path / "crypttab"  # not written
    clevis = tmp_path / "clevis"
    clevis.mkdir()
    (clevis / "luks-home.jwe").write_text("{\"pin\":\"tpm2\"}\n")
    found = await _run(crypttab, clevis)
    assert len(found) == 1
    f = found[0]
    assert f.algorithm == "TPM-sealed"
    assert f.evidence["volume"] == "luks-home"
    assert str(clevis / "luks-home.jwe") in f.evidence["path"]


@pytest.mark.asyncio
async def test_plain_passphrase_mapping_no_finding(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text("luks-root /dev/sda2 none luks\n")
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert found == []


@pytest.mark.asyncio
async def test_keyfile_none_alone_no_finding(tmp_path: Path):
    # keyfile "none" without a tpm2 option means interactive passphrase.
    crypttab = tmp_path / "crypttab"
    crypttab.write_text("luks-root /dev/sda2 none\n")
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert found == []


@pytest.mark.asyncio
async def test_comments_and_blank_lines_ignored(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text(
        "# luks-old /dev/sda1 none tpm2-device=auto\n"
        "\n"
        "   \n"
        "luks-root /dev/sda2 none luks\n"
    )
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert found == []


@pytest.mark.asyncio
async def test_multiple_mappings_one_finding_each(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text(
        "a /dev/sda1 none tpm2-device=auto,luks\n"
        "b /dev/sda2 none luks\n"
        "c /dev/sda3 none luks,tpm2\n"
    )
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    vols = sorted(f.evidence["volume"] for f in found)
    assert vols == ["a", "c"]


@pytest.mark.asyncio
async def test_oversized_crypttab_skipped(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text(
        "luks-root /dev/sda2 none tpm2-device=auto,luks\n"
        + "# pad\n" * 500_000
    )
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert found == []


@pytest.mark.asyncio
async def test_malformed_line_does_not_crash(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text("onlyname\nname dev\ngood /dev/sda1 none tpm2\n")
    clevis = tmp_path / "clevis"
    found = await _run(crypttab, clevis)
    assert len(found) == 1
    assert found[0].evidence["volume"] == "good"


@pytest.mark.asyncio
async def test_absent_sources_emit_nothing(tmp_path: Path):
    crypttab = tmp_path / "crypttab"  # not written
    clevis = tmp_path / "clevis"  # not created
    found = await _run(crypttab, clevis)
    assert found == []


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = HostTpmSealedKeys(paths=[tmp_path / "crypttab", tmp_path / "clevis"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_crypttab_present(tmp_path: Path):
    crypttab = tmp_path / "crypttab"
    crypttab.write_text("luks-root /dev/sda2 none luks\n")
    probe = HostTpmSealedKeys(paths=[crypttab, tmp_path / "clevis"])
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_true_when_clevis_dir_present(tmp_path: Path):
    clevis = tmp_path / "clevis"
    clevis.mkdir()
    probe = HostTpmSealedKeys(paths=[tmp_path / "crypttab", clevis])
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_default_paths_used_when_none(tmp_path: Path):
    probe = HostTpmSealedKeys()
    assert Path("/etc/crypttab") in probe.paths
    assert Path("/etc/clevis") in probe.paths
