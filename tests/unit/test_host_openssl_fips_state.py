"""Tests for host.openssl.fips_state (FIPS 140 mode detection)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_fips_state import HostOpenSSLFipsState

# A binary name that resolves nowhere -> shutil.which() returns None, so the
# provider list is never run unless we stub it explicitly.
_NO_OPENSSL = "no-such-openssl-binary-xyz"


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _write_flag(tmp_path: Path, value: str) -> Path:
    path = tmp_path / "fips_enabled"
    path.write_text(value + "\n")
    return path


async def _run(probe: HostOpenSSLFipsState) -> list:
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


def _probe(flag_path: Path, *, providers_fips: bool = False) -> HostOpenSSLFipsState:
    probe = HostOpenSSLFipsState(openssl=_NO_OPENSSL, fips_enabled_path=flag_path)

    async def _fake_providers() -> tuple[bool, str]:
        return providers_fips, "stub list -providers"

    probe._read_providers = _fake_providers  # type: ignore[method-assign]
    return probe


@pytest.mark.asyncio
async def test_kernel_flag_one_is_active(tmp_path: Path):
    found = await _run(_probe(_write_flag(tmp_path, "1")))
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED
    assert found[0].evidence["fips_enabled"] == "1"
    assert "FIPS" in found[0].title


@pytest.mark.asyncio
async def test_kernel_flag_zero_is_inactive(tmp_path: Path):
    found = await _run(_probe(_write_flag(tmp_path, "0")))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert found[0].severity is Severity.INFO
    assert found[0].title == "FIPS mode not enabled"
    assert found[0].evidence["fips_enabled"] == "0"
    assert found[0].evidence["fips_provider_loaded"] is False


@pytest.mark.asyncio
async def test_provider_loaded_activates_without_kernel_flag(tmp_path: Path):
    found = await _run(_probe(_write_flag(tmp_path, "0"), providers_fips=True))
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].evidence["fips_provider_loaded"] is True


@pytest.mark.asyncio
async def test_absent_flag_with_no_openssl_is_inactive(tmp_path: Path):
    # No fips_enabled file and no openssl provider -> single INFO finding.
    found = await _run(_probe(tmp_path / "fips_enabled"))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert found[0].evidence["fips_enabled"] is None


@pytest.mark.asyncio
async def test_single_finding_emitted_when_active(tmp_path: Path):
    found = await _run(_probe(_write_flag(tmp_path, "1"), providers_fips=True))
    assert len(found) == 1


@pytest.mark.asyncio
async def test_applies_true_when_flag_file_exists(tmp_path: Path):
    probe = HostOpenSSLFipsState(
        openssl=_NO_OPENSSL, fips_enabled_path=_write_flag(tmp_path, "1")
    )
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_false_when_nothing_present(tmp_path: Path):
    probe = HostOpenSSLFipsState(
        openssl=_NO_OPENSSL, fips_enabled_path=tmp_path / "fips_enabled"
    )
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_providers_have_fips_parsing():
    have = HostOpenSSLFipsState._providers_have_fips
    assert have("Providers:\n  fips\n    name: OpenSSL FIPS Provider\n") is True
    assert have("Providers:\n  default\n  base\n") is False
