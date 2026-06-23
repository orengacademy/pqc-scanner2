"""Tests for fs.keyref.cloud (cloud KMS / HSM key-reference discovery)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_keyref_cloud import FsKeyrefCloud


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(root: Path) -> list:
    found: list = []
    probe = FsKeyrefCloud(roots=[root])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_aws_kms_arn(tmp_path: Path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_kms_key" "k" {}\n'
        'key_id = "arn:aws:kms:ap-southeast-1:123456789012:key/abcd-1234"\n'
    )
    found = await _run(tmp_path)
    assert len(found) == 1
    assert found[0].algorithm == "AWS-KMS"
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED
    assert "arn:aws:kms" in found[0].evidence["reference"]


@pytest.mark.asyncio
async def test_azure_keyvault_url(tmp_path: Path):
    (tmp_path / "app.yaml").write_text(
        "key: https://myvault.vault.azure.net/keys/signing-key/abc123\n"
    )
    found = await _run(tmp_path)
    assert found[0].algorithm == "Azure-KeyVault"


@pytest.mark.asyncio
async def test_gcp_kms_resource(tmp_path: Path):
    (tmp_path / "vars.tfvars").write_text(
        'kms = "projects/p1/locations/asia/keyRings/r1/cryptoKeys/k1"\n'
    )
    found = await _run(tmp_path)
    assert found[0].algorithm == "GCP-KMS"


@pytest.mark.asyncio
async def test_pkcs11_uri(tmp_path: Path):
    (tmp_path / "engine.conf").write_text(
        "key = pkcs11:token=mytoken;object=signing;type=private\n"
    )
    found = await _run(tmp_path)
    assert found[0].algorithm == "PKCS11/HSM"


@pytest.mark.asyncio
async def test_key_spec_recorded(tmp_path: Path):
    (tmp_path / "kms.tf").write_text(
        'customer_master_key_spec = "RSA_2048"\n'
        'arn = "arn:aws:kms:us-east-1:123456789012:key/xyz"\n'
    )
    found = await _run(tmp_path)
    assert "RSA_2048" in found[0].evidence["key_specs"]


@pytest.mark.asyncio
async def test_no_refs_and_ignored_extension(tmp_path: Path):
    (tmp_path / "readme.txt").write_text("arn:aws:kms:us-east-1:1:key/x\n")  # not allowlisted
    (tmp_path / "empty.tf").write_text("resource {}\n")
    assert await _run(tmp_path) == []


@pytest.mark.asyncio
async def test_applies(tmp_path: Path):
    (tmp_path / "x.tf").write_text("\n")
    assert await FsKeyrefCloud(roots=[tmp_path]).applies(_ctx()) is True
    assert await FsKeyrefCloud(roots=[tmp_path / "absent"]).applies(_ctx()) is False
