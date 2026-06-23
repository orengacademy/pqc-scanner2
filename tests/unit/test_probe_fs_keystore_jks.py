"""Tests for fs.keystore.jks (Java keystore magic-byte inventory, no pyjks)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_keystore_jks import FsKeystoreJks


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(root: Path) -> list:
    found: list = []
    probe = FsKeystoreJks(roots=[root])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_jks_magic_detected(tmp_path: Path):
    (tmp_path / "app.jks").write_bytes(b"\xfe\xed\xfe\xed\x00\x00\x00\x02rest")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm == "JKS"
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_jceks_magic_detected(tmp_path: Path):
    (tmp_path / "store.jceks").write_bytes(b"\xce\xce\xce\xce\x00\x00\x00\x01rest")
    found = await _run(tmp_path)
    assert found[0].algorithm == "JCEKS"


@pytest.mark.asyncio
async def test_cacerts_by_name_and_magic(tmp_path: Path):
    # Java's default truststore is named "cacerts" with no extension.
    (tmp_path / "cacerts").write_bytes(b"\xfe\xed\xfe\xed\x00\x00\x00\x02xx")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm == "JKS"


@pytest.mark.asyncio
async def test_non_keystore_ignored(tmp_path: Path):
    # Right extension but wrong magic -> not a Java keystore.
    (tmp_path / "fake.jks").write_bytes(b"PK\x03\x04 this is a zip")
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_applies(tmp_path: Path):
    (tmp_path / "x.jks").write_bytes(b"\xfe\xed\xfe\xed")
    assert await FsKeystoreJks(roots=[tmp_path]).applies(_ctx()) is True
    assert await FsKeystoreJks(roots=[tmp_path / "no"]).applies(_ctx()) is False
