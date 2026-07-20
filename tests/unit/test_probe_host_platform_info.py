import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_platform_info import HostPlatformInfo


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(probe: HostPlatformInfo) -> list:
    found: list = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_always_applies():
    assert await HostPlatformInfo().applies(_ctx()) is True


@pytest.mark.asyncio
async def test_emits_one_info_finding_on_any_platform():
    found = await _run(HostPlatformInfo())
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.INFO
    assert f.evidence["os"]
    assert f.evidence["arch"]
    assert f.evidence["python"]


@pytest.mark.asyncio
async def test_overrides_pin_values():
    found = await _run(HostPlatformInfo(overrides={
        "os": "Windows", "os_release": "10", "arch": "AMD64",
        "python": "3.11.9",
    }))
    f = found[0]
    assert f.evidence["os"] == "Windows"
    assert "Windows 10 (AMD64)" in f.title
    assert "Python 3.11.9" in f.title
