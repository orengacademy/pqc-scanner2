"""Tests for host.ssh.binary_caps (`ssh -Q kex` PQC capability detection)."""
import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_ssh_binary_caps import HostSshBinaryCaps

_CLASSICAL = (
    "curve25519-sha256\n"
    "curve25519-sha256@libssh.org\n"
    "ecdh-sha2-nistp256\n"
    "diffie-hellman-group14-sha256\n"
)
_VERSION = "OpenSSH_9.9p1, OpenSSL 3.0.13 30 Jan 2024"


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(kex_output: str) -> list:
    found: list = []
    probe = HostSshBinaryCaps(
        ssh="/no/such/ssh", kex_output=kex_output, version=_VERSION,
    )
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_mlkem_kex_is_pqc_ready():
    found = await _run("mlkem768x25519-sha256\n" + _CLASSICAL)
    assert len(found) == 1
    assert found[0].classification is Classification.PQC_READY
    assert found[0].severity is Severity.INFO
    assert "mlkem768x25519-sha256" in found[0].evidence["pqc_kex"]


@pytest.mark.asyncio
async def test_sntrup_kex_is_pqc_ready():
    found = await _run("sntrup761x25519-sha512@openssh.com\n" + _CLASSICAL)
    assert len(found) == 1
    assert found[0].classification is Classification.PQC_READY
    assert any("sntrup761" in k for k in found[0].evidence["pqc_kex"])


@pytest.mark.asyncio
async def test_classical_only_is_medium_gap():
    found = await _run(_CLASSICAL)
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED
    assert found[0].evidence["version"] == _VERSION


@pytest.mark.asyncio
async def test_empty_output_emits_nothing():
    found = await _run("")
    assert found == []


@pytest.mark.asyncio
async def test_applies_true_with_injected_output():
    probe = HostSshBinaryCaps(ssh="/no/such/ssh", kex_output=_CLASSICAL)
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_applies_false_when_no_ssh():
    probe = HostSshBinaryCaps(ssh="/no/such/ssh")
    assert await probe.applies(_ctx()) is False
