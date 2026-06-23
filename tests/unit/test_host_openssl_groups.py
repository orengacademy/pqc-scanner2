from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_openssl_groups import HostOpenSSLGroups


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def test_parse_policy_extracts_keys():
    text = (
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2\n"
        "MaxProtocol = TLSv1.3\n"
        "CipherString = DEFAULT:@SECLEVEL=2\n"
        "Groups = x25519:secp256r1\n"
        "SignatureAlgorithms = ECDSA+SHA256:RSA+SHA256\n"
    )
    policy = HostOpenSSLGroups()._parse_policy(text)
    assert policy["minprotocol"] == "TLSv1.2"
    assert policy["maxprotocol"] == "TLSv1.3"
    assert policy["cipherstring"] == "DEFAULT:@SECLEVEL=2"
    assert policy["groups"] == "x25519:secp256r1"
    assert policy["signaturealgorithms"] == "ECDSA+SHA256:RSA+SHA256"


def test_parse_policy_ignores_comments_and_other_sections():
    text = (
        "# top comment\n"
        "[other_sect]\n"
        "MinProtocol = TLSv1\n"
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2  # inline comment\n"
        "; semicolon comment\n"
        "Groups = x25519\n"
    )
    policy = HostOpenSSLGroups()._parse_policy(text)
    assert policy["minprotocol"] == "TLSv1.2"
    assert policy["groups"] == "x25519"


def test_seclevel_extraction():
    probe = HostOpenSSLGroups()
    assert probe._seclevel("DEFAULT:@SECLEVEL=0") == 0
    assert probe._seclevel("DEFAULT:@SECLEVEL=1") == 1
    assert probe._seclevel("DEFAULT:@SECLEVEL=2") == 2
    assert probe._seclevel("DEFAULT") is None


def test_groups_has_pqc():
    probe = HostOpenSSLGroups()
    assert probe._groups_has_pqc("X25519MLKEM768:x25519") is True
    assert probe._groups_has_pqc("x25519_kyber768:secp256r1") is True
    assert probe._groups_has_pqc("x25519:secp256r1:ffdhe2048") is False


@pytest.mark.asyncio
async def test_weak_minprotocol_emits_med(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.1\n"
        "CipherString = DEFAULT:@SECLEVEL=2\n"
        "Groups = X25519MLKEM768\n"
    )
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    weak = [f for f in found if "minprotocol" in f.title.lower()]
    assert weak
    assert weak[0].classification == Classification.SEDERHANA
    assert weak[0].severity == Severity.MED


@pytest.mark.asyncio
async def test_minprotocol_unset_emits_med(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[system_default_sect]\n"
        "CipherString = DEFAULT:@SECLEVEL=2\n"
        "Groups = X25519MLKEM768\n"
    )
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    assert any("minprotocol" in f.title.lower() for f in found)


@pytest.mark.asyncio
async def test_low_seclevel_emits_high(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2\n"
        "CipherString = DEFAULT:@SECLEVEL=1\n"
        "Groups = X25519MLKEM768\n"
    )
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    sec = [f for f in found if "seclevel" in f.title.lower()]
    assert sec
    assert sec[0].classification == Classification.TINGGI
    assert sec[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_classical_only_groups_emits_med(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2\n"
        "CipherString = DEFAULT:@SECLEVEL=2\n"
        "Groups = x25519:secp256r1:ffdhe2048\n"
    )
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    grp = [f for f in found if "pqc groups" in f.title.lower()]
    assert grp
    assert grp[0].classification == Classification.SEDERHANA
    assert grp[0].severity == Severity.MED


@pytest.mark.asyncio
async def test_hybrid_groups_emits_pqc_ready(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2\n"
        "CipherString = DEFAULT:@SECLEVEL=2\n"
        "Groups = X25519MLKEM768:x25519:secp256r1\n"
    )
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    ready = [f for f in found if f.classification == Classification.PQC_READY]
    assert ready
    assert ready[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_clean_config_no_findings(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text(
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2\n"
        "MaxProtocol = TLSv1.3\n"
        "CipherString = DEFAULT:@SECLEVEL=2\n"
        "Groups = X25519MLKEM768:x25519\n"
    )
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    # Only the PQC_READY informational finding, no weakness findings.
    assert all(f.classification == Classification.PQC_READY for f in found)


@pytest.mark.asyncio
async def test_applies_false_when_no_roots_exist(tmp_path: Path):
    probe = HostOpenSSLGroups(roots=[tmp_path / "missing.cnf"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text("[system_default_sect]\nMinProtocol = TLSv1.2\n")
    probe = HostOpenSSLGroups(roots=[cfg])
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_no_policy_section_no_crash(tmp_path: Path):
    cfg = tmp_path / "openssl.cnf"
    cfg.write_text("[some_other]\nfoo = bar\n")
    found: list = []
    probe = HostOpenSSLGroups(roots=[cfg])
    await probe.run(_ctx(), emit=found.append)
    # No system_default_sect -> nothing to assess.
    assert found == []
