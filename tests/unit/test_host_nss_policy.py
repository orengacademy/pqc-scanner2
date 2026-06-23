"""Tests for host.nss.policy (NSS system crypto-policy back-end)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_nss_policy import HostNssPolicy


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _write(tmp_path: Path, contents: str) -> Path:
    cfg = tmp_path / "nss.config"
    cfg.write_text(contents)
    return cfg


async def _run(cfg: Path) -> list:
    found: list = []
    probe = HostNssPolicy(config_path=cfg)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


def _by_algo(found: list, algo: str):
    return [f for f in found if f.algorithm == algo]


@pytest.mark.asyncio
async def test_weak_tls_floor_is_medium(tmp_path: Path):
    cfg = _write(tmp_path, "allow=AES-256-GCM:HMAC-SHA256:RSA-MIN=2048\nmin-tls=tls1.0\n")
    found = await _run(cfg)
    floor = _by_algo(found, "nss/min-tls")
    assert len(floor) == 1
    assert floor[0].classification is Classification.SEDERHANA
    assert floor[0].severity is Severity.MED
    assert floor[0].evidence["min-tls"] == "tls1.0"


@pytest.mark.asyncio
async def test_unset_tls_floor_flagged(tmp_path: Path):
    cfg = _write(tmp_path, "allow=AES-256-GCM:HMAC-SHA256:RSA-MIN=2048\n")
    found = await _run(cfg)
    floor = _by_algo(found, "nss/min-tls")
    assert len(floor) == 1
    assert floor[0].evidence["min-tls"] == "(unset)"
    assert floor[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_modern_floor_not_flagged(tmp_path: Path):
    cfg = _write(tmp_path, "allow=AES-256-GCM:HMAC-SHA256:RSA-MIN=2048\nmin-tls=tls1.2\n")
    found = await _run(cfg)
    assert _by_algo(found, "nss/min-tls") == []


@pytest.mark.asyncio
async def test_camelcase_mintls(tmp_path: Path):
    cfg = _write(tmp_path, "allow=AES-256-GCM:RSA-MIN=2048\nminTLS=tls1.2\n")
    found = await _run(cfg)
    assert _by_algo(found, "nss/min-tls") == []


@pytest.mark.asyncio
async def test_weak_primitives_high(tmp_path: Path):
    cfg = _write(
        tmp_path,
        "allow=RC4:DES:MD5:AES-256-GCM:RSA-MIN=2048\nmin-tls=tls1.2\n",
    )
    found = await _run(cfg)
    weak = _by_algo(found, "nss/allow")
    assert len(weak) == 1
    assert weak[0].classification is Classification.TINGGI
    assert weak[0].severity is Severity.HIGH
    assert "RC4" in weak[0].evidence["weak"]
    assert "DES" in weak[0].evidence["weak"]
    assert "MD5" in weak[0].evidence["weak"]


@pytest.mark.asyncio
async def test_sha1_signatures_high(tmp_path: Path):
    cfg = _write(
        tmp_path,
        "allow=AES-256-GCM:RSA-SHA1:HMAC-SHA256:RSA-MIN=2048\nmin-tls=tls1.2\n",
    )
    found = await _run(cfg)
    weak = _by_algo(found, "nss/allow")
    assert len(weak) == 1
    assert "SHA-1 signatures" in weak[0].evidence["weak"]


@pytest.mark.asyncio
async def test_hmac_sha1_alone_not_flagged(tmp_path: Path):
    # HMAC-SHA1 as a MAC is not a SHA-1 *signature* — must not trip the rule.
    cfg = _write(
        tmp_path,
        "allow=AES-256-GCM:HMAC-SHA1:RSA-MIN=2048\nmin-tls=tls1.2\n",
    )
    found = await _run(cfg)
    assert _by_algo(found, "nss/allow") == []


@pytest.mark.asyncio
async def test_weak_dh_rsa_min_high(tmp_path: Path):
    cfg = _write(
        tmp_path,
        "allow=AES-256-GCM:DH-MIN=1024:RSA-MIN=1536\nmin-tls=tls1.2\n",
    )
    found = await _run(cfg)
    weak = _by_algo(found, "nss/allow")
    assert len(weak) == 1
    assert "DH-MIN=1024" in weak[0].evidence["weak"]
    assert "RSA-MIN=1536" in weak[0].evidence["weak"]


@pytest.mark.asyncio
async def test_strong_allow_list_not_flagged(tmp_path: Path):
    cfg = _write(
        tmp_path,
        "allow=AES-256-GCM:HMAC-SHA256:DH-MIN=2048:RSA-MIN=2048\nmin-tls=tls1.2\n",
    )
    found = await _run(cfg)
    assert _by_algo(found, "nss/allow") == []


@pytest.mark.asyncio
async def test_classical_only_note_present(tmp_path: Path):
    cfg = _write(tmp_path, "allow=RC4:RSA-MIN=2048\nmin-tls=tls1.2\n")
    found = await _run(cfg)
    weak = _by_algo(found, "nss/allow")
    assert "classical-only" in weak[0].evidence["note"]


@pytest.mark.asyncio
async def test_comments_and_blank_lines_ignored(tmp_path: Path):
    cfg = _write(
        tmp_path,
        "# system policy\n\nallow=AES-256-GCM:RSA-MIN=2048\nmin-tls=tls1.2\n",
    )
    found = await _run(cfg)
    assert found == []


@pytest.mark.asyncio
async def test_absent_file_emits_nothing(tmp_path: Path):
    found = await _run(tmp_path / "missing.config")
    assert found == []


@pytest.mark.asyncio
async def test_applies_true_when_present(tmp_path: Path):
    cfg = _write(tmp_path, "min-tls=tls1.2\n")
    probe = HostNssPolicy(config_path=cfg)
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = HostNssPolicy(config_path=tmp_path / "missing.config")
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_default_path_is_system_nss_config():
    probe = HostNssPolicy()
    assert str(probe.config_path) == "/etc/crypto-policies/back-ends/nss.config"
