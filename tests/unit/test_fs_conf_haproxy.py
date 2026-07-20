from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_haproxy import FsConfHaproxy


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsConfHaproxy(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_weak_bind_ciphers_flagged(tmp_path: Path):
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text(
        "global\n"
        "    ssl-default-bind-ciphers ECDHE-RSA-AES256-GCM-SHA384:RC4:3DES\n"
    )
    found = await _run([cfg])
    by_alg = {f.algorithm: f for f in found}
    # RC4 / 3DES are broken-now (SANGAT_TINGGI); the ECDHE-RSA suite uses
    # quantum-vulnerable ECDH key establishment (TINGGI) — a PQC scanner
    # flags it too.
    assert by_alg["RC4"].classification is Classification.SANGAT_TINGGI
    assert by_alg["RC4"].severity is Severity.CRIT
    assert by_alg["3DES"].classification is Classification.SANGAT_TINGGI
    assert by_alg["ECDHE-RSA-AES256-GCM-SHA384"].classification is Classification.TINGGI
    assert all(f.evidence["directive"] == "ssl-default-bind-ciphers" for f in found)


@pytest.mark.asyncio
async def test_weak_ssl_min_ver_flagged(tmp_path: Path):
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text(
        "global\n"
        "    ssl-default-bind-options ssl-min-ver TLSv1.0\n"
    )
    found = await _run([cfg])
    assert len(found) == 1
    assert found[0].algorithm == "TLSV1.0"
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT


@pytest.mark.asyncio
async def test_no_tlsv13_and_force_tlsv10_flagged(tmp_path: Path):
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text(
        "frontend fe\n"
        "    bind :443 ssl crt /etc/ssl/site.pem no-tlsv13\n"
        "    bind :8443 ssl crt /etc/ssl/site.pem force-tlsv10\n"
    )
    found = await _run([cfg])
    assert {f.algorithm for f in found} == {"TLSV1.3", "TLSV1.0"}
    assert all(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_safe_config_emits_nothing(tmp_path: Path):
    # A config with only TLS 1.3 cipher *suites* (which name no key-exchange)
    # and a >=TLS1.2 floor has nothing for the probe to flag. (TLS 1.2 ECDHE
    # suites would be flagged as quantum-vulnerable — see the weak-cipher test.)
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text(
        "global\n"
        "    ssl-default-bind-options ssl-min-ver TLSv1.2 no-sslv3 no-tlsv10\n"
        "    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n"
    )
    found = await _run([cfg])
    assert found == []


@pytest.mark.asyncio
async def test_directory_root_scans_cfg_files(tmp_path: Path):
    (tmp_path / "10-tls.cfg").write_text(
        "global\n"
        "    ssl-default-bind-ciphers RC4\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].algorithm == "RC4"


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = FsConfHaproxy(roots=[tmp_path / "nope" / "haproxy.cfg"])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_present(tmp_path: Path):
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text("global\n")
    probe = FsConfHaproxy(roots=[cfg])
    assert await probe.applies(_ctx()) is True
