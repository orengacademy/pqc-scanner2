"""Tests for fs.iac.terraform (Terraform IaC crypto config)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_iac_terraform import FsIacTerraform


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsIacTerraform(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_kms_rsa_2048_is_weak(tmp_path: Path):
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "weak" {\n'
        '  customer_master_key_spec = "RSA_2048"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.evidence["resource"] == "aws_kms_key"
    assert f.evidence["field"] == "customer_master_key_spec"
    assert f.evidence["line"] == 2


@pytest.mark.asyncio
async def test_kms_rsa_4096_is_quantum_vulnerable(tmp_path: Path):
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "big" {\n'
        '  customer_master_key_spec = "RSA_4096"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_kms_symmetric_default_is_not_flagged(tmp_path: Path):
    # AES-256 symmetric CMK — quantum-safe, must produce NO finding.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "ok" {\n'
        '  customer_master_key_spec = "SYMMETRIC_DEFAULT"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_kms_ecc_is_quantum_vulnerable(tmp_path: Path):
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "ecc" {\n'
        '  customer_master_key_spec = "ECC_NIST_P256"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_tls_private_key_rsa_2048(tmp_path: Path):
    (tmp_path / "key.tf").write_text(
        'resource "tls_private_key" "k" {\n'
        '  algorithm = "RSA"\n'
        "  rsa_bits  = 2048\n"
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].algorithm == "RSA-2048"


@pytest.mark.asyncio
async def test_tls_private_key_ecdsa(tmp_path: Path):
    (tmp_path / "key.tf").write_text(
        'resource "tls_private_key" "k" {\n'
        '  algorithm   = "ECDSA"\n'
        '  ecdsa_curve = "P384"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_legacy_alb_ssl_policy_flagged(tmp_path: Path):
    (tmp_path / "lb.tf").write_text(
        'resource "aws_lb_listener" "l" {\n'
        '  ssl_policy = "ELBSecurityPolicy-2016-08"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].evidence["field"] == "ssl_policy"


@pytest.mark.asyncio
async def test_modern_tls13_ssl_policy_not_flagged(tmp_path: Path):
    (tmp_path / "lb.tf").write_text(
        'resource "aws_lb_listener" "l" {\n'
        '  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_azurerm_key_vault_rsa(tmp_path: Path):
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "k" {\n'
        '  key_type = "RSA"\n'
        "  key_size = 2048\n"
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].algorithm == "RSA-2048"


@pytest.mark.asyncio
async def test_tf_json_kms_rsa(tmp_path: Path):
    (tmp_path / "kms.tf.json").write_text(
        '{"resource": {"aws_kms_key": {"weak": {'
        '"customer_master_key_spec": "RSA_2048"}}}}\n'
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_excluded_dirs_skipped(tmp_path: Path):
    d = tmp_path / ".terraform" / "modules"
    d.mkdir(parents=True)
    (d / "kms.tf").write_text(
        'resource "aws_kms_key" "x" {\n'
        '  customer_master_key_spec = "RSA_2048"\n'
        "}\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_missing_root_and_malformed(tmp_path: Path):
    missing = tmp_path / "nope"
    probe = FsIacTerraform(roots=[missing])
    assert await probe.applies(_ctx()) is False
    # malformed HCL must not crash
    (tmp_path / "broken.tf").write_text('resource "aws_kms_key" "x" {\n  customer')
    found = await _run([tmp_path])
    assert found == []
