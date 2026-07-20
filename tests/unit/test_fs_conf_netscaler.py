from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_netscaler import FsConfNetscaler


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsConfNetscaler(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_weak_protocols_flagged(tmp_path: Path):
    cfg = tmp_path / "ns.conf"
    cfg.write_text("set ssl vserver vs1 -ssl3 ENABLED -tls11 ENABLED -tls12 ENABLED\n")
    found = await _run([cfg])
    by_alg = {f.algorithm: f for f in found}
    assert by_alg["SSLV3"].classification is Classification.SANGAT_TINGGI
    assert by_alg["SSLV3"].severity is Severity.CRIT
    assert by_alg["TLSV1.1"].classification is Classification.SANGAT_TINGGI
    # tls12 ENABLED is fine — not flagged.
    assert "TLSV1.2" not in by_alg
    assert all(f.evidence["entity"] == "vs1" for f in found)


@pytest.mark.asyncio
async def test_tls13_disabled_noted(tmp_path: Path):
    cfg = tmp_path / "ns.conf"
    cfg.write_text("set ssl vserver vs1 -tls12 ENABLED -tls13 DISABLED\n")
    found = await _run([cfg])
    assert len(found) == 1
    assert found[0].algorithm == "TLSV1.3"
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_ssl3_3des_cipher_flagged(tmp_path: Path):
    cfg = tmp_path / "ns.conf"
    cfg.write_text(
        "add ssl cipher g\n"
        "bind ssl cipher g -cipherName SSL3-DES-CBC3-SHA\n"
    )
    found = await _run([cfg])
    assert len(found) == 1
    assert found[0].algorithm == "SSL3-DES-CBC3-SHA"
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT
    assert found[0].evidence == {
        "path": str(cfg), "entity": "g", "directive": "cipherName",
    }


@pytest.mark.asyncio
async def test_rc4_cipher_flagged(tmp_path: Path):
    cfg = tmp_path / "ns.conf"
    cfg.write_text("bind ssl vserver vs1 -cipherName RC4-MD5\n")
    found = await _run([cfg])
    assert len(found) == 1
    assert found[0].algorithm == "RC4-MD5"
    assert found[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_certkey_binding_ignored(tmp_path: Path):
    # A cert binding names no cipher — nothing to classify.
    cfg = tmp_path / "ns.conf"
    cfg.write_text("bind ssl vserver vs1 -certkeyName mycert\n")
    found = await _run([cfg])
    assert found == []


@pytest.mark.asyncio
async def test_hardened_config_no_weak_findings(tmp_path: Path):
    cfg = tmp_path / "ns.conf"
    cfg.write_text(
        "set ssl vserver vs1 -tls12 ENABLED -tls13 ENABLED\n"
        "bind ssl vserver vs1 -cipherName TLS1.2-ECDHE-RSA-AES256-GCM-SHA384\n"
    )
    found = await _run([cfg])
    # No broken-now (SANGAT_TINGGI / CRIT) findings and no disabled-TLS1.3 note.
    assert not any(f.classification is Classification.SANGAT_TINGGI for f in found)
    assert not any(f.severity is Severity.CRIT for f in found)
    # The classical ECDHE key exchange is still quantum-vulnerable (TINGGI) —
    # a PQC scanner surfaces it, matching the haproxy/nginx probes.
    assert all(f.classification is Classification.TINGGI for f in found)


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = FsConfNetscaler(roots=[tmp_path / "nope" / "ns.conf"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_present(tmp_path: Path):
    cfg = tmp_path / "ns.conf"
    cfg.write_text("set ssl vserver vs1 -tls12 ENABLED\n")
    probe = FsConfNetscaler(roots=[cfg])
    assert await probe.applies(_ctx()) is True
