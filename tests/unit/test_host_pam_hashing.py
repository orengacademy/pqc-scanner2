"""Tests for host.pam.hashing (system password-hash algorithm posture)."""
import os
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_pam_hashing import HostPamHashing


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(tmp_path: Path) -> list[Finding]:
    found: list[Finding] = []
    probe = HostPamHashing(
        login_defs=tmp_path / "login.defs",
        pam_dir=tmp_path / "pam.d",
        shadow=tmp_path / "shadow",
    )
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_login_defs_md5_is_crit(tmp_path: Path):
    (tmp_path / "login.defs").write_text("# comment\nENCRYPT_METHOD MD5\n")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT
    assert found[0].algorithm == "crypt/MD5"


@pytest.mark.asyncio
async def test_login_defs_sha256_is_medium(tmp_path: Path):
    (tmp_path / "login.defs").write_text("ENCRYPT_METHOD SHA256\n")
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].algorithm == "crypt/SHA256"


@pytest.mark.asyncio
async def test_safe_config_emits_nothing(tmp_path: Path):
    (tmp_path / "login.defs").write_text("ENCRYPT_METHOD YESCRYPT\n")
    pam_dir = tmp_path / "pam.d"
    pam_dir.mkdir()
    (pam_dir / "common-password").write_text(
        "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"
    )
    (tmp_path / "shadow").write_text(
        "root:$6$saltsalt$hashhashhash:19000:0:99999:7:::\n"
        "alice:$y$j9T$salt$hashhashhash:19000:0:99999:7:::\n"
        "daemon:*:19000:0:99999:7:::\n"
    )
    found = await _run(tmp_path)
    assert found == []


@pytest.mark.asyncio
async def test_pam_unix_md5_is_crit(tmp_path: Path):
    pam_dir = tmp_path / "pam.d"
    pam_dir.mkdir()
    (pam_dir / "common-password").write_text(
        "# comment md5 in comment is ignored\n"
        "password [success=1 default=ignore] pam_unix.so obscure md5\n"
    )
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].algorithm == "crypt/MD5"
    assert "common-password" in found[0].evidence["path"]


@pytest.mark.asyncio
async def test_shadow_weak_schemes_dedup_and_redacted(tmp_path: Path):
    (tmp_path / "shadow").write_text(
        "alice:$1$salt$md5hashvalue:19000:0:99999:7:::\n"
        "bob:$1$salt$othermd5hash:19000:0:99999:7:::\n"
        "carol:WovA9wOPBhLpU:19000:0:99999:7:::\n"
        "dave:$6$salt$sha512hashvalue:19000:0:99999:7:::\n"
        "eve:$5$salt$sha256hashvalue:19000:0:99999:7:::\n"
        "locked:!:19000:0:99999:7:::\n"
    )
    found = await _run(tmp_path)
    by_alg = {f.algorithm: f for f in found}
    assert set(by_alg) == {"crypt/MD5", "crypt/DES", "crypt/SHA256"}
    assert by_alg["crypt/MD5"].classification is Classification.SANGAT_TINGGI
    assert by_alg["crypt/MD5"].evidence["accounts"] == 2
    assert by_alg["crypt/DES"].classification is Classification.SANGAT_TINGGI
    assert by_alg["crypt/SHA256"].classification is Classification.SEDERHANA
    # Redaction: no username or hash material may leak into evidence.
    for f in found:
        blob = str(f.evidence) + f.title
        for secret in ("alice", "bob", "carol", "eve", "md5hashvalue", "WovA9wOPBhLpU", "salt"):
            assert secret not in blob


@pytest.mark.asyncio
async def test_shadow_permission_denied_does_not_crash(tmp_path: Path):
    if os.geteuid() == 0:
        pytest.skip("chmod 000 is not enforced for root")
    shadow = tmp_path / "shadow"
    shadow.write_text("alice:$1$salt$md5hashvalue:19000:0:99999:7:::\n")
    shadow.chmod(0o000)
    try:
        found = await _run(tmp_path)
    finally:
        shadow.chmod(0o600)
    assert found == []


@pytest.mark.asyncio
async def test_applies_and_absent_emit_nothing(tmp_path: Path):
    probe = HostPamHashing(
        login_defs=tmp_path / "login.defs",
        pam_dir=tmp_path / "pam.d",
        shadow=tmp_path / "shadow",
    )
    assert await probe.applies(_ctx()) is False
    found: list[Finding] = []
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    assert found == []
    (tmp_path / "login.defs").write_text("ENCRYPT_METHOD SHA512\n")
    assert await probe.applies(_ctx()) is True
