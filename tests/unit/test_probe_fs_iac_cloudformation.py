"""Tests for fs.iac.cloudformation (CloudFormation + cert-manager crypto config)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_iac_cloudformation import FsIacCloudformation


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsIacCloudformation(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_cfn_kms_rsa_2048_weak(tmp_path: Path):
    (tmp_path / "kms.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  MyKey:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      KeySpec: RSA_2048\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.severity is Severity.CRIT
    assert f.evidence["resource_type"] == "AWS::KMS::Key"
    assert f.evidence["logical_id_or_kind"] == "MyKey"
    assert f.evidence["field"] == "KeySpec"


@pytest.mark.asyncio
async def test_cfn_kms_symmetric_not_flagged(tmp_path: Path):
    # AES-256 symmetric CMK — quantum-safe, NO finding.
    (tmp_path / "kms.yaml").write_text(
        "Resources:\n"
        "  MyKey:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      KeySpec: SYMMETRIC_DEFAULT\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_cfn_kms_ecc_json(tmp_path: Path):
    (tmp_path / "kms.json").write_text(
        '{"Resources": {"MyKey": {"Type": "AWS::KMS::Key",'
        '"Properties": {"KeySpec": "ECC_NIST_P384"}}}}\n'
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_cfn_listener_legacy_ssl_policy(tmp_path: Path):
    (tmp_path / "lb.yaml").write_text(
        "Resources:\n"
        "  L:\n"
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n"
        "    Properties:\n"
        "      SslPolicy: ELBSecurityPolicy-TLS-1-1-2017-01\n"
        "      Protocol: HTTPS\n"
    )
    found = await _run([tmp_path])
    tls = [f for f in found if f.evidence["field"] == "SslPolicy"]
    assert len(tls) == 1
    assert tls[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_cfn_listener_http_info(tmp_path: Path):
    (tmp_path / "lb.yaml").write_text(
        "Resources:\n"
        "  L:\n"
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n"
        "    Properties:\n"
        "      Protocol: HTTP\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert found[0].severity is Severity.INFO


@pytest.mark.asyncio
async def test_cfn_intrinsic_tags_do_not_crash(tmp_path: Path):
    (tmp_path / "kms.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  MyKey:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      KeySpec: RSA_3072\n"
        "      KeyPolicy: !Ref SomePolicy\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_certmanager_rsa_2048_multidoc(tmp_path: Path):
    (tmp_path / "certs.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Namespace\n"
        "metadata:\n"
        "  name: pki\n"
        "---\n"
        "apiVersion: cert-manager.io/v1\n"
        "kind: Certificate\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  privateKey:\n"
        "    algorithm: RSA\n"
        "    size: 2048\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SANGAT_TINGGI
    assert f.evidence["logical_id_or_kind"] == "Certificate"
    assert f.evidence["field"] == "spec.privateKey.algorithm"


@pytest.mark.asyncio
async def test_certmanager_ecdsa_flagged(tmp_path: Path):
    (tmp_path / "cert.yaml").write_text(
        "apiVersion: cert-manager.io/v1\n"
        "kind: Certificate\n"
        "spec:\n"
        "  privateKey:\n"
        "    algorithm: ECDSA\n"
        "    size: 384\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI


@pytest.mark.asyncio
async def test_non_cfn_yaml_ignored(tmp_path: Path):
    # A plain deployment manifest that is neither CFN nor cert-manager.
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_missing_root_and_malformed(tmp_path: Path):
    missing = tmp_path / "nope"
    probe = FsIacCloudformation(roots=[missing])
    assert await probe.applies(_ctx()) is False
    (tmp_path / "broken.yaml").write_text("Resources: {AWS:: [unclosed\n")
    (tmp_path / "broken.json").write_text('{"Resources": {AWS::}\n')
    found = await _run([tmp_path])
    assert found == []
