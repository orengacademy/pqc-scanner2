"""Tests for host.windows.schannel (Windows SCHANNEL registry crypto posture).

All tests inject a config dict, so no real registry / winreg is touched — the
probe is exercised end-to-end on Linux CI.
"""
import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_windows_schannel import HostWindowsSchannel


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(config: dict | None) -> list:
    found: list = []
    probe = HostWindowsSchannel(schannel_config=config)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


def _by_alg(found: list) -> dict:
    return {f.algorithm: f for f in found}


_WEAK_CONFIG = {
    "Protocols": {
        "SSL 3.0": {"Server": {"Enabled": 1}},
        "TLS 1.0": {"Client": {"Enabled": 1}},
        "TLS 1.2": {"Client": {"Enabled": 1}, "Server": {"Enabled": 1}},
    },
    "Ciphers": {
        "RC4 128/128": {"Enabled": 1},
        "Triple DES 168": {"Enabled": 1},
        "AES 256/256": {"Enabled": 1},
    },
    "Hashes": {"MD5": {"Enabled": 1}},
    "KeyExchangeAlgorithms": {"PKCS": {"Enabled": 1}},
}

_HARDENED_CONFIG = {
    "Protocols": {
        "TLS 1.2": {"Client": {"Enabled": 1}, "Server": {"Enabled": 1}},
        "TLS 1.3": {"Client": {"Enabled": 1}, "Server": {"Enabled": 1}},
        "SSL 3.0": {"Server": {"Enabled": 0}, "Client": {"Enabled": 0}},
        "TLS 1.0": {"Client": {"Enabled": 0}},
    },
    "Ciphers": {"AES 256/256": {"Enabled": 1}},
}


@pytest.mark.asyncio
async def test_weak_protocols_are_critical():
    found = _by_alg(await _run(_WEAK_CONFIG))
    assert "SCHANNEL/Protocols/SSL 3.0" in found
    assert "SCHANNEL/Protocols/TLS 1.0" in found
    for alg in ("SCHANNEL/Protocols/SSL 3.0", "SCHANNEL/Protocols/TLS 1.0"):
        assert found[alg].classification is Classification.SANGAT_TINGGI
        assert found[alg].severity is Severity.CRIT
    # TLS 1.2 is enabled and correct — never a finding.
    assert "SCHANNEL/Protocols/TLS 1.2" not in found


@pytest.mark.asyncio
async def test_weak_ciphers_rc4_and_3des():
    found = _by_alg(await _run(_WEAK_CONFIG))
    rc4 = found["SCHANNEL/Ciphers/RC4 128/128"]
    assert rc4.classification is Classification.SANGAT_TINGGI
    assert rc4.severity is Severity.CRIT
    tdes = found["SCHANNEL/Ciphers/Triple DES 168"]
    assert tdes.classification is Classification.TINGGI
    assert tdes.severity is Severity.HIGH
    # AES-256 is strong — no finding.
    assert "SCHANNEL/Ciphers/AES 256/256" not in found


@pytest.mark.asyncio
async def test_md5_hash_is_critical():
    found = _by_alg(await _run(_WEAK_CONFIG))
    md5 = found["SCHANNEL/Hashes/MD5"]
    assert md5.classification is Classification.SANGAT_TINGGI
    assert md5.severity is Severity.CRIT


@pytest.mark.asyncio
async def test_classical_key_exchange_is_high():
    found = _by_alg(await _run(_WEAK_CONFIG))
    pkcs = found["SCHANNEL/KeyExchangeAlgorithms/PKCS"]
    assert pkcs.classification is Classification.TINGGI
    assert pkcs.severity is Severity.HIGH
    assert "harvest-now" in pkcs.evidence["note"].lower()


@pytest.mark.asyncio
async def test_weak_config_total_findings():
    found = await _run(_WEAK_CONFIG)
    # SSL3, TLS1.0, RC4, 3DES, MD5, PKCS -> 6 weak findings; TLS1.2 + AES256 skip.
    algs = {f.algorithm for f in found}
    assert algs == {
        "SCHANNEL/Protocols/SSL 3.0",
        "SCHANNEL/Protocols/TLS 1.0",
        "SCHANNEL/Ciphers/RC4 128/128",
        "SCHANNEL/Ciphers/Triple DES 168",
        "SCHANNEL/Hashes/MD5",
        "SCHANNEL/KeyExchangeAlgorithms/PKCS",
    }


@pytest.mark.asyncio
async def test_hardened_config_no_weak_findings():
    found = await _run(_HARDENED_CONFIG)
    assert found == []


@pytest.mark.asyncio
async def test_disabled_weak_cipher_is_not_flagged():
    found = await _run({"Ciphers": {"RC4 128/128": {"Enabled": 0}}})
    assert found == []


@pytest.mark.asyncio
async def test_empty_config_does_not_crash():
    assert await _run({}) == []


@pytest.mark.asyncio
async def test_malformed_config_is_guarded():
    # Non-dict sections / entries must never raise.
    found = await _run({
        "Protocols": None,
        "Ciphers": {"RC4 128/128": "garbage", "NULL": {"Enabled": "x"}},
        "Hashes": ["not", "a", "dict"],
        "KeyExchangeAlgorithms": {"PKCS": {}},
    })
    assert found == []


@pytest.mark.asyncio
async def test_applies_true_when_config_injected():
    probe = HostWindowsSchannel(schannel_config={})
    assert await probe.applies(_ctx()) is True


@pytest.mark.asyncio
async def test_finding_carries_registry_evidence_and_remediation():
    found = _by_alg(await _run(_WEAK_CONFIG))
    rc4 = found["SCHANNEL/Ciphers/RC4 128/128"]
    assert rc4.probe_id == "host.windows.schannel"
    assert rc4.evidence["section"] == "Ciphers"
    assert rc4.evidence["registry_key"] == "SCHANNEL/Ciphers/RC4 128/128"
    assert "SCHANNEL" in rc4.remediation["snippet"]
