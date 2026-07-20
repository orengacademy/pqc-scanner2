"""Tests for host.cloud_kms (live cloud KMS / Key Vault enumeration).

All cloud access goes through an injected `runner(argv) -> str | None`
returning canned JSON keyed by the argv tokens, so no real cloud / CLI is
touched.
"""
from __future__ import annotations

import json

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_cloud_kms import HostCloudKms


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(runner) -> list[Finding]:
    found: list[Finding] = []
    probe = HostCloudKms(runner=runner)
    await probe.run(_ctx(), emit=found.append)
    return found


def _aws_runner():
    def runner(argv: list[str]) -> str | None:
        if "kms" in argv and "list-keys" in argv:
            return json.dumps({"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]})
        if "kms" in argv and "describe-key" in argv:
            key_id = argv[argv.index("--key-id") + 1]
            spec = "RSA_2048" if key_id == "k1" else "SYMMETRIC_DEFAULT"
            return json.dumps({"KeyMetadata": {
                "KeyId": key_id,
                "KeySpec": spec,
                "Arn": f"arn:aws:kms:us-east-1:123456789012:key/{key_id}",
            }})
        return None
    return runner


def _azure_runner():
    def runner(argv: list[str]) -> str | None:
        if "keyvault" in argv and "list" in argv and "key" not in argv:
            return json.dumps([{"name": "vault1"}])
        if "keyvault" in argv and "key" in argv and "list" in argv:
            return json.dumps([{"kid": "https://vault1.vault.azure.net/keys/mykey"}])
        if "keyvault" in argv and "key" in argv and "show" in argv:
            return json.dumps({"key": {"kty": "EC", "crv": "P-256"}})
        return None
    return runner


async def test_aws_rsa_and_symmetric_keys():
    found = await _run(_aws_runner())
    assert len(found) == 2

    by_key = {f.evidence["key_id"]: f for f in found}

    rsa = by_key["k1"]
    assert rsa.algorithm == "RSA-2048"
    # RSA-2048 (<3072) is broken-now-and-quantum -> SANGAT_TINGGI / CRIT.
    assert rsa.classification is Classification.SANGAT_TINGGI
    assert rsa.severity is Severity.CRIT
    assert rsa.evidence["provider"] == "aws"
    assert rsa.evidence["key_spec"] == "RSA_2048"
    assert rsa.evidence["region"] == "us-east-1"

    sym = by_key["k2"]
    assert sym.algorithm == "AES-256"
    assert sym.classification is Classification.RENDAH
    assert sym.severity is Severity.LOW
    assert sym.evidence["key_spec"] == "SYMMETRIC_DEFAULT"


async def test_aws_rsa_is_at_least_high_severity():
    found = await _run(_aws_runner())
    rsa = next(f for f in found if f.evidence["key_id"] == "k1")
    # Spec: RSA-2048 emits a SANGAT_TINGGI/TINGGI (i.e. CRIT/HIGH) finding.
    assert rsa.severity.numeric >= Severity.HIGH.numeric
    assert rsa.classification in {Classification.SANGAT_TINGGI, Classification.TINGGI}


async def test_azure_ec_key():
    found = await _run(_azure_runner())
    assert len(found) == 1
    ec = found[0]
    assert ec.algorithm == "ECDSA-P-256"
    assert ec.classification is Classification.TINGGI
    assert ec.severity is Severity.HIGH
    assert ec.evidence["provider"] == "azure"
    assert ec.evidence["vault"] == "vault1"
    assert ec.evidence["key_id"] == "mykey"
    assert ec.evidence["key_spec"] == "EC"


async def test_unauthenticated_runner_returns_nothing():
    found = await _run(lambda argv: None)
    assert found == []


async def test_applies_true_when_runner_injected():
    probe = HostCloudKms(runner=lambda argv: None)
    assert await probe.applies(_ctx()) is True


async def test_probe_metadata():
    probe = HostCloudKms(runner=lambda argv: None)
    assert probe.id == "host.cloud_kms"
    assert probe.framework_tags == ("nist-ir-8547:kms", "mykripto:kms")
