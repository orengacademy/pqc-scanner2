"""Tests for fs.cert.privkey_encrypted (encrypted private-key at-rest inventory)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_cert_privkey_encrypted import FsCertPrivkeyEncrypted


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(root: Path) -> list:
    found: list = []
    probe = FsCertPrivkeyEncrypted(roots=[root])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_pkcs8_encrypted_is_medium(tmp_path: Path):
    (tmp_path / "server.key").write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkq...\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm == "PKCS8-PBES2"
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED


@pytest.mark.asyncio
async def test_legacy_3des_is_high(tmp_path: Path):
    (tmp_path / "old.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: DES-EDE3-CBC,9F8E7D6C5B4A3210\n"
        "\n"
        "base64keymaterial...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    found = await _run(tmp_path)
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH
    assert "DES-EDE3-CBC" in found[0].algorithm


@pytest.mark.asyncio
async def test_legacy_aes_is_medium(tmp_path: Path):
    (tmp_path / "aes.pem").write_text(
        "-----BEGIN EC PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,0011223344556677\n"
        "\n"
        "base64...\n"
        "-----END EC PRIVATE KEY-----\n"
    )
    found = await _run(tmp_path)
    assert found[0].classification is Classification.SEDERHANA
    assert "AES-256-CBC" in found[0].algorithm


@pytest.mark.asyncio
async def test_unencrypted_key_ignored(tmp_path: Path):
    (tmp_path / "plain.key").write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n"
    )
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_non_key_file_ignored(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("DEK-Info: DES-EDE3-CBC, not a key\n")
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_applies(tmp_path: Path):
    (tmp_path / "x.key").write_text("\n")
    assert await FsCertPrivkeyEncrypted(roots=[tmp_path]).applies(_ctx()) is True
    assert await FsCertPrivkeyEncrypted(roots=[tmp_path / "no"]).applies(_ctx()) is False
