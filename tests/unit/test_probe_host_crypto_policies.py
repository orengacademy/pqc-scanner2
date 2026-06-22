"""Tests for host.crypto_policies.profile (RHEL/Fedora crypto-policies)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_crypto_policies import HostCryptoPolicies

# A path that does not exist -> shutil.which() returns None, so the probe
# falls back to reading the injected config_dir instead of running the CLI.
_NO_CLI = "/no/such/update-crypto-policies"


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _write_current(tmp_path: Path, value: str) -> Path:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "current").write_text(value + "\n")
    return tmp_path


async def _run(config_dir: Path) -> list:
    found: list = []
    probe = HostCryptoPolicies(command=_NO_CLI, config_dir=config_dir)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_legacy_is_high(tmp_path: Path):
    found = await _run(_write_current(tmp_path, "LEGACY"))
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH
    assert found[0].evidence["base"] == "LEGACY"
    assert found[0].algorithm == "crypto-policies/LEGACY"


@pytest.mark.asyncio
async def test_default_is_medium(tmp_path: Path):
    found = await _run(_write_current(tmp_path, "DEFAULT"))
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_future_is_low(tmp_path: Path):
    found = await _run(_write_current(tmp_path, "FUTURE"))
    assert found[0].classification is Classification.RENDAH
    assert found[0].severity is Severity.LOW


@pytest.mark.asyncio
async def test_sha1_submodule_escalates(tmp_path: Path):
    found = await _run(_write_current(tmp_path, "DEFAULT:SHA1"))
    assert found[0].classification is Classification.TINGGI
    assert found[0].evidence["submodules"] == ["SHA1"]
    assert "SHA-1" in found[0].evidence["note"]


@pytest.mark.asyncio
async def test_base_config_fallback_when_no_state(tmp_path: Path):
    # Only /etc/crypto-policies/config exists (base policy, no submodules).
    (tmp_path / "config").write_text("LEGACY\n")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].evidence["base"] == "LEGACY"


@pytest.mark.asyncio
async def test_absent_emits_nothing(tmp_path: Path):
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = HostCryptoPolicies(command=_NO_CLI, config_dir=tmp_path)
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_with_config_file(tmp_path: Path):
    (tmp_path / "config").write_text("DEFAULT\n")
    probe = HostCryptoPolicies(command=_NO_CLI, config_dir=tmp_path)
    assert await probe.applies(_ctx()) is True
