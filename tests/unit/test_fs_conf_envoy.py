"""Tests for fs.conf.envoy (Envoy proxy TLS config)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_envoy import FsConfEnvoy


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsConfEnvoy(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_flags_weak_minimum_protocol(tmp_path: Path):
    cfg = tmp_path / "envoy.yaml"
    cfg.write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - filter_chains:\n"
        "        - transport_socket:\n"
        "            typed_config:\n"
        "              common_tls_context:\n"
        "                tls_params:\n"
        "                  tls_minimum_protocol_version: TLSv1_0\n"
        "                  tls_maximum_protocol_version: TLSv1_1\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 2
    assert all(f.classification is Classification.SANGAT_TINGGI for f in found)
    assert all(f.severity is Severity.CRIT for f in found)
    directives = {f.evidence["directive"] for f in found}
    assert directives == {"tls_minimum_protocol_version", "tls_maximum_protocol_version"}


@pytest.mark.asyncio
async def test_flags_weak_cipher_suites_from_json(tmp_path: Path):
    cfg = tmp_path / "envoy.json"
    cfg.write_text(
        '{"common_tls_context": {"tls_params": {'
        '"cipher_suites": ["RC4", "AES-128-CBC", "AES-256-GCM"]}}}\n'
    )
    found = await _run([tmp_path])
    by_alg = {f.algorithm: f for f in found}
    assert by_alg["RC4"].classification is Classification.SANGAT_TINGGI
    assert by_alg["RC4"].severity is Severity.CRIT
    assert by_alg["AES-128-CBC"].classification is Classification.TINGGI
    assert by_alg["AES-128-CBC"].severity is Severity.HIGH
    assert "AES-256-GCM" not in by_alg  # rendah — below emit threshold


@pytest.mark.asyncio
async def test_flags_weak_ciphers_in_colon_joined_string(tmp_path: Path):
    cfg = tmp_path / "envoy.yaml"
    cfg.write_text(
        "common_tls_context:\n"
        "  tls_params:\n"
        '    cipher_suites: "3DES:AES-128-CBC"\n'
    )
    found = await _run([tmp_path])
    assert {f.algorithm for f in found} == {"3DES", "AES-128-CBC"}


@pytest.mark.asyncio
async def test_flags_classical_ecdh_curves(tmp_path: Path):
    cfg = tmp_path / "envoy.yaml"
    cfg.write_text(
        "common_tls_context:\n"
        "  tls_params:\n"
        "    ecdh_curves:\n"
        "      - P-256\n"
        "      - X25519\n"
        "      - X25519MLKEM768\n"
    )
    found = await _run([tmp_path])
    by_alg = {f.algorithm: f for f in found}
    assert by_alg["ECDH-P256"].classification is Classification.TINGGI
    assert by_alg["X25519"].classification is Classification.TINGGI
    assert "X25519MLKEM768" not in by_alg  # pqc-ready hybrid is not flagged
    assert len(found) == 2


@pytest.mark.asyncio
async def test_safe_config_emits_nothing(tmp_path: Path):
    cfg = tmp_path / "envoy.yaml"
    # PQC-ready posture: a modern TLS floor and a PQC-hybrid ECDH group. A
    # classical ECDHE cipher suite would be flagged as quantum-vulnerable, so
    # a genuinely "safe" config relies on the hybrid group here.
    cfg.write_text(
        "common_tls_context:\n"
        "  tls_params:\n"
        "    tls_minimum_protocol_version: TLSv1_2\n"
        "    tls_maximum_protocol_version: TLSv1_3\n"
        "    ecdh_curves:\n"
        "      - X25519MLKEM768\n"
    )
    found = await _run([tmp_path])
    assert found == []


@pytest.mark.asyncio
async def test_missing_root_emits_nothing(tmp_path: Path):
    missing = tmp_path / "nope"
    probe = FsConfEnvoy(roots=[missing])
    assert await probe.applies(_ctx()) is False
    found = await _run([missing])
    assert found == []


@pytest.mark.asyncio
async def test_malformed_config_does_not_crash(tmp_path: Path):
    (tmp_path / "templated.yaml").write_text("tls_params: [unclosed\n  {{ env \"CIPHERS\" }}\n")
    (tmp_path / "broken.json").write_text('{"tls_params": {"cipher_suites": [}\n')
    found = await _run([tmp_path])
    assert found == []
