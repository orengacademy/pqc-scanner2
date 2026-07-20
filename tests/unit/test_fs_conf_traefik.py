"""Tests for fs.conf.traefik (Traefik TLS options config)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_traefik import FsConfTraefik


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsConfTraefik(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_flags_weak_min_version_yaml(tmp_path: Path):
    cfg = tmp_path / "dynamic.yml"
    cfg.write_text(
        "tls:\n"
        "  options:\n"
        "    default:\n"
        "      minVersion: VersionTLS10\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT
    assert found[0].evidence["option"] == "default"
    assert found[0].evidence["directive"] == "minVersion"


@pytest.mark.asyncio
async def test_flags_static_rsa_suite_toml(tmp_path: Path):
    cfg = tmp_path / "traefik.toml"
    cfg.write_text(
        "[tls.options.modern]\n"
        'minVersion = "VersionTLS12"\n'
        "cipherSuites = [\n"
        '  "TLS_RSA_WITH_AES_128_GCM_SHA256",\n'
        '  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",\n'
        "]\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].algorithm == "TLS_RSA_WITH_AES_128_GCM_SHA256"
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_flags_sha1_and_3des_suites_as_critical(tmp_path: Path):
    cfg = tmp_path / "dynamic.yaml"
    cfg.write_text(
        "tls:\n"
        "  options:\n"
        "    legacy:\n"
        "      cipherSuites:\n"
        "        - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA\n"
        "        - TLS_RSA_WITH_3DES_EDE_CBC_SHA\n"
    )
    found = await _run([tmp_path])
    by_alg = {f.algorithm: f for f in found}
    assert by_alg["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"].classification is Classification.SANGAT_TINGGI
    assert by_alg["TLS_RSA_WITH_3DES_EDE_CBC_SHA"].classification is Classification.SANGAT_TINGGI
    assert len(found) == 2


@pytest.mark.asyncio
async def test_flags_classical_curve_preferences(tmp_path: Path):
    cfg = tmp_path / "dynamic.yml"
    cfg.write_text(
        "tls:\n"
        "  options:\n"
        "    default:\n"
        "      curvePreferences:\n"
        "        - CurveP256\n"
        "        - CurveP384\n"
        "        - X25519\n"
    )
    found = await _run([tmp_path])
    assert {f.algorithm for f in found} == {"CurveP256", "CurveP384"}
    assert all(f.classification is Classification.TINGGI for f in found)


@pytest.mark.asyncio
async def test_safe_config_emits_nothing(tmp_path: Path):
    cfg = tmp_path / "dynamic.yml"
    cfg.write_text(
        "tls:\n"
        "  options:\n"
        "    modern:\n"
        "      minVersion: VersionTLS13\n"
        "      cipherSuites:\n"
        "        - TLS_AES_256_GCM_SHA384\n"
        "        - TLS_CHACHA20_POLY1305_SHA256\n"
        "      curvePreferences:\n"
        "        - X25519\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_missing_root_emits_nothing(tmp_path: Path):
    missing = tmp_path / "nope"
    probe = FsConfTraefik(roots=[missing])
    assert await probe.applies(_ctx()) is False
    found = await _run([missing])
    assert found == []


@pytest.mark.asyncio
async def test_malformed_config_does_not_crash(tmp_path: Path):
    (tmp_path / "broken.yml").write_text("tls:\n  options: [unclosed\n    {{ env }}\n")
    (tmp_path / "broken.toml").write_text("[tls.options\nminVersion =\n")
    found = await _run([tmp_path])
    assert found == []
