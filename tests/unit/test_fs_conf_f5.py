from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_f5 import FsConfF5


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsConfF5(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_no_tlsv13_option_flagged(tmp_path: Path):
    cfg = tmp_path / "bigip.conf"
    cfg.write_text(
        "ltm profile client-ssl /Common/myprofile {\n"
        "    ciphers DEFAULT\n"
        "    options { dont-insert-empty-fragments no-tlsv1.3 }\n"
        "    ssl-forward-proxy enabled\n"
        "}\n"
    )
    found = await _run([cfg])
    by_alg = {f.algorithm: f for f in found}
    assert "TLSV1.3" in by_alg
    assert by_alg["TLSV1.3"].classification is Classification.SANGAT_TINGGI
    assert by_alg["TLSV1.3"].severity is Severity.CRIT
    assert by_alg["TLSV1.3"].evidence["profile"] == "/Common/myprofile"


@pytest.mark.asyncio
async def test_weak_ciphers_flagged(tmp_path: Path):
    cfg = tmp_path / "bigip.conf"
    cfg.write_text(
        "ltm profile client-ssl /Common/legacy {\n"
        "    ciphers DEFAULT:RC4:3DES\n"
        "}\n"
    )
    found = await _run([cfg])
    by_alg = {f.algorithm: f for f in found}
    assert by_alg["RC4"].classification is Classification.SANGAT_TINGGI
    assert by_alg["RC4"].severity is Severity.CRIT
    assert by_alg["3DES"].classification is Classification.SANGAT_TINGGI
    assert all(f.evidence["directive"] == "ciphers" for f in found)
    # DEFAULT alias word is skipped.
    assert "DEFAULT" not in by_alg


@pytest.mark.asyncio
async def test_hardened_profile_emits_nothing(tmp_path: Path):
    cfg = tmp_path / "bigip.conf"
    cfg.write_text(
        "ltm profile client-ssl /Common/secure {\n"
        "    ciphers ECDHE+AES-GCM\n"
        "    options { dont-insert-empty-fragments }\n"
        "}\n"
    )
    found = await _run([cfg])
    # ECDHE (quantum-vulnerable key establishment) is TINGGI and a PQC scanner
    # flags it; AES-GCM is not weak. Ensure no SANGAT_TINGGI / protocol findings.
    assert all(f.classification is not Classification.SANGAT_TINGGI for f in found)
    assert all(f.evidence.get("directive") != "options no-tlsv1.3" for f in found)


@pytest.mark.asyncio
async def test_server_ssl_export_null_flagged(tmp_path: Path):
    cfg = tmp_path / "bigip.conf"
    cfg.write_text(
        "ltm profile server-ssl /Common/backend {\n"
        "    ciphers HIGH:EXPORT:!NULL:SSLv3\n"
        "}\n"
    )
    found = await _run([cfg])
    algs = {f.algorithm for f in found}
    assert "EXPORT" in algs
    assert "NULL" in algs  # `!NULL` -> NULL after prefix strip
    assert "SSLV3" in algs
    assert all(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_directory_root_scans_nested_bigip_conf(tmp_path: Path):
    part = tmp_path / "partitions" / "MyOrg"
    part.mkdir(parents=True)
    (part / "bigip.conf").write_text(
        "ltm profile client-ssl /MyOrg/p {\n"
        "    ciphers DEFAULT:RC4\n"
        "}\n"
    )
    found = await _run([tmp_path / "partitions"])
    assert len(found) == 1
    assert found[0].algorithm == "RC4"


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = FsConfF5(roots=[tmp_path / "nope" / "bigip.conf"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_present(tmp_path: Path):
    cfg = tmp_path / "bigip.conf"
    cfg.write_text("ltm profile client-ssl /Common/x {\n}\n")
    probe = FsConfF5(roots=[cfg])
    assert await probe.applies(_ctx()) is True
