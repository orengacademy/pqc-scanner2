"""Tests for host.rng.config (kernel entropy pool / hardware RNG posture)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_rng_config import HostRngConfig


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(
    entropy_path: Path,
    hwrng_path: Path,
    rng_daemon_paths: list[Path],
) -> list[Finding]:
    found: list[Finding] = []
    probe = HostRngConfig(
        entropy_path=entropy_path,
        hwrng_path=hwrng_path,
        rng_daemon_paths=rng_daemon_paths,
    )
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_low_entropy_is_medium(tmp_path: Path):
    entropy = tmp_path / "entropy_avail"
    entropy.write_text("100\n")
    hwrng = tmp_path / "rng_current"
    hwrng.write_text("tpm-rng-0\n")
    found = await _run(entropy, hwrng, [])
    weak = [f for f in found if f.algorithm == "rng/entropy"]
    assert len(weak) == 1
    assert weak[0].classification is Classification.SEDERHANA
    assert weak[0].severity is Severity.MED
    assert weak[0].evidence["entropy_avail"] == 100


@pytest.mark.asyncio
async def test_healthy_posture_emits_nothing(tmp_path: Path):
    entropy = tmp_path / "entropy_avail"
    entropy.write_text("3858\n")
    hwrng = tmp_path / "rng_current"
    hwrng.write_text("tpm-rng-0\n")
    found = await _run(entropy, hwrng, [])
    assert found == []


@pytest.mark.asyncio
async def test_hwrng_none_is_info(tmp_path: Path):
    entropy = tmp_path / "entropy_avail"
    entropy.write_text("3858\n")
    hwrng = tmp_path / "rng_current"
    hwrng.write_text("none\n")
    daemon = tmp_path / "rngd"
    daemon.write_text("")
    found = await _run(entropy, hwrng, [daemon])
    assert len(found) == 1
    assert found[0].algorithm == "rng/hw_random"
    assert found[0].classification is Classification.INFO
    assert found[0].severity is Severity.INFO


@pytest.mark.asyncio
async def test_no_hwrng_and_no_daemon_emits_info_notes(tmp_path: Path):
    entropy = tmp_path / "entropy_avail"
    entropy.write_text("3858\n")
    found = await _run(entropy, tmp_path / "rng_current", [tmp_path / "rngd"])
    algorithms = {f.algorithm for f in found}
    assert algorithms == {"rng/hw_random", "rng/daemon"}
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_missing_entropy_file_does_not_crash(tmp_path: Path):
    hwrng = tmp_path / "rng_current"
    hwrng.write_text("tpm-rng-0\n")
    found = await _run(tmp_path / "entropy_avail", hwrng, [])
    assert [f for f in found if f.algorithm == "rng/entropy"] == []


@pytest.mark.asyncio
async def test_applies(tmp_path: Path):
    probe = HostRngConfig(
        entropy_path=tmp_path / "entropy_avail",
        hwrng_path=tmp_path / "rng_current",
        rng_daemon_paths=[],
    )
    assert await probe.applies(_ctx()) is False
    (tmp_path / "entropy_avail").write_text("3858\n")
    assert await probe.applies(_ctx()) is True
