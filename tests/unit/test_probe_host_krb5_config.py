"""Tests for host.krb5.config (Kerberos krb5.conf enctype + PKINIT parse)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_krb5_config import HostKrb5Config


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(cfg: Path) -> list:
    found: list = []
    probe = HostKrb5Config(config_paths=[cfg])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_weak_enctypes_flagged(tmp_path: Path):
    cfg = tmp_path / "krb5.conf"
    cfg.write_text(
        "[libdefaults]\n"
        "  permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac des3-cbc-sha1 "
        "des-cbc-crc\n"
    )
    found = await _run(cfg)
    algs = {f.algorithm for f in found}
    assert {"RC4", "3DES", "DES"}.issubset(algs)
    # DES is catastrophic -> CRIT; RC4/3DES -> HIGH.
    des = next(f for f in found if f.algorithm == "DES")
    assert des.classification is Classification.SANGAT_TINGGI
    assert des.severity is Severity.CRIT
    rc4 = next(f for f in found if f.algorithm == "RC4")
    assert rc4.severity is Severity.HIGH
    # aes256 is strong -> not flagged.
    assert "AES-256" not in algs


@pytest.mark.asyncio
async def test_allow_weak_crypto_flagged(tmp_path: Path):
    cfg = tmp_path / "krb5.conf"
    cfg.write_text("[libdefaults]\n  allow_weak_crypto = true\n")
    found = await _run(cfg)
    assert any("allow_weak_crypto" in f.algorithm for f in found)
    awc = next(f for f in found if "allow_weak_crypto" in f.algorithm)
    assert awc.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_pkinit_flagged_quantum_vulnerable(tmp_path: Path):
    cfg = tmp_path / "krb5.conf"
    cfg.write_text(
        "[libdefaults]\n"
        "  default_realm = EXAMPLE.COM\n"
        "  pkinit_anchors = FILE:/etc/krb5/cacert.pem\n"
    )
    found = await _run(cfg)
    pk = [f for f in found if "PKINIT" in f.algorithm]
    assert len(pk) == 1
    assert pk[0].classification is Classification.SEDERHANA
    assert pk[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_modern_config_no_findings(tmp_path: Path):
    cfg = tmp_path / "krb5.conf"
    cfg.write_text(
        "[libdefaults]\n"
        "  permitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128\n"
        "  allow_weak_crypto = false\n"
        "  # rc4-hmac is only mentioned in this comment\n"
    )
    found = await _run(cfg)
    assert found == []


@pytest.mark.asyncio
async def test_applies(tmp_path: Path):
    cfg = tmp_path / "krb5.conf"
    cfg.write_text("[libdefaults]\n")
    assert await HostKrb5Config(config_paths=[cfg]).applies(_ctx()) is True
    assert await HostKrb5Config(
        config_paths=[tmp_path / "absent.conf"]
    ).applies(_ctx()) is False
