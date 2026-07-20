"""Tests for host.ssh.moduli (/etc/ssh/moduli DH group-exchange strength)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_ssh_moduli import HostSshModuli

_MODULUS = "F" * 64  # placeholder hex modulus; content is irrelevant to the probe


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _line(bits: int) -> str:
    return f"20260101000000 2 6 100 {bits} 2 {_MODULUS}"


def _write_moduli(tmp_path: Path, bits: list[int], header: str = "") -> Path:
    path = tmp_path / "moduli"
    body = "".join(_line(b) + "\n" for b in bits)
    path.write_text(header + body)
    return path


async def _run(path: Path) -> list:
    found: list = []
    probe = HostSshModuli(path=path)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_sub_2048_groups_are_critical(tmp_path: Path):
    found = await _run(_write_moduli(tmp_path, [1023, 1535, 4095]))
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT
    assert found[0].algorithm == "DH-1023"
    assert found[0].evidence["min_bits"] == 1023
    assert found[0].evidence["weak_line_count"] == 2


@pytest.mark.asyncio
async def test_2047_group_is_high(tmp_path: Path):
    found = await _run(_write_moduli(tmp_path, [2047, 3071, 4095]))
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH
    assert found[0].algorithm == "DH-2047"
    assert found[0].evidence["min_bits"] == 2047
    # 3071 is the standard 3072-bit group (column stores prime bits - 1) -> not weak.
    assert found[0].evidence["weak_line_count"] == 1


@pytest.mark.asyncio
async def test_all_strong_groups_emit_nothing(tmp_path: Path):
    found = await _run(_write_moduli(tmp_path, [3072, 4095, 6143, 8191]))
    assert found == []


@pytest.mark.asyncio
async def test_comments_and_blank_lines_ignored(tmp_path: Path):
    header = "# Time Type Tests Tries Size Generator Modulus\n\n   \n# 1024 in a comment\n"
    found = await _run(_write_moduli(tmp_path, [4095], header=header))
    assert found == []


@pytest.mark.asyncio
async def test_applies_false_when_missing(tmp_path: Path):
    probe = HostSshModuli(path=tmp_path / "moduli")
    assert await probe.applies(_ctx()) is False
    assert await _run(tmp_path / "moduli") == []
