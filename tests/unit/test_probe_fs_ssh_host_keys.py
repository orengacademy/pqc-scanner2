"""Tests for fs.ssh.host_keys (on-disk SSH public key inventory)."""
import base64
import struct
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_ssh_host_keys import FsSshHostKeys


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _rsa_pub(modulus_bytes: int, comment: str = "root@host") -> str:
    """Build a syntactically valid ssh-rsa public key line with a modulus of
    the given byte length (modulus_bytes * 8 bits)."""
    def field(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b
    e = b"\x01\x00\x01"
    n = b"\x80" + b"\x00" * (modulus_bytes - 1)  # top bit set -> full bit length
    n_mpint = b"\x00" + n                          # mpint: prepend 0x00 if high bit set
    blob = field(b"ssh-rsa") + field(e) + field(n_mpint)
    return "ssh-rsa " + base64.b64encode(blob).decode() + " " + comment


async def _run(root: Path) -> list:
    found: list = []
    probe = FsSshHostKeys(roots=[root])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_rsa_2048_is_medium(tmp_path: Path):
    (tmp_path / "ssh_host_rsa_key.pub").write_text(_rsa_pub(256) + "\n")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm == "RSA-2048"
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_rsa_1024_is_high(tmp_path: Path):
    (tmp_path / "weak.pub").write_text(_rsa_pub(128) + "\n")
    found = await _run(tmp_path)
    assert found[0].algorithm == "RSA-1024"
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_ed25519_is_medium(tmp_path: Path):
    (tmp_path / "ssh_host_ed25519_key.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc root@host\n"
    )
    found = await _run(tmp_path)
    assert found[0].algorithm == "Ed25519"
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_dss_is_high(tmp_path: Path):
    (tmp_path / "old.pub").write_text("ssh-dss AAAAB3NzaC1kc3MAAACBdummy legacy@host\n")
    found = await _run(tmp_path)
    assert found[0].algorithm == "DSA"
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_ecdsa_curve_named(tmp_path: Path):
    (tmp_path / "ec.pub").write_text(
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODRdummy a@b\n"
    )
    found = await _run(tmp_path)
    assert found[0].algorithm == "ECDSA-P384"
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_authorized_keys_with_options(tmp_path: Path):
    # authorized_keys lines can carry an options prefix before the key type.
    (tmp_path / "authorized_keys").write_text(
        'no-pty,no-X11-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyz user@laptop\n'
    )
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm == "Ed25519"


@pytest.mark.asyncio
async def test_comments_and_blank_skipped(tmp_path: Path):
    (tmp_path / "x.pub").write_text("# a comment\n\n   \n")
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_applies(tmp_path: Path):
    (tmp_path / "k.pub").write_text(_rsa_pub(256) + "\n")
    assert await FsSshHostKeys(roots=[tmp_path]).applies(_ctx()) is True
    assert await FsSshHostKeys(roots=[tmp_path / "absent"]).applies(_ctx()) is False
