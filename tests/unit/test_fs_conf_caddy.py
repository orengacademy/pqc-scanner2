import json
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.fs_conf_caddy import FsConfCaddy


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


async def _run(roots: list[Path]) -> list:
    found: list = []
    probe = FsConfCaddy(roots=roots)
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_weak_protocols_flagged(tmp_path: Path):
    (tmp_path / "Caddyfile").write_text(
        "example.com {\n"
        "  tls {\n"
        "    protocols tls1.0 tls1.2\n"
        "  }\n"
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].algorithm == "TLS1.0"
    assert found[0].classification is Classification.SANGAT_TINGGI
    assert found[0].severity is Severity.CRIT


@pytest.mark.asyncio
async def test_weak_key_type_flagged(tmp_path: Path):
    (tmp_path / "Caddyfile").write_text(
        "example.com {\n"
        "  tls {\n"
        "    key_type rsa2048\n"
        "  }\n"
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].algorithm == "RSA-2048"
    assert found[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_weak_curves_flagged_but_hybrid_list_is_ok(tmp_path: Path):
    (tmp_path / "Caddyfile").write_text(
        "weak.example.com {\n"
        "  tls {\n"
        "    curves secp256r1\n"
        "  }\n"
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].algorithm == "ECDSA-P256"
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH

    (tmp_path / "Caddyfile").write_text(
        "hybrid.example.com {\n"
        "  tls {\n"
        "    curves x25519mlkem768 secp256r1\n"
        "  }\n"
        "}\n"
    )
    assert await _run([tmp_path]) == []


@pytest.mark.asyncio
async def test_weak_cipher_suites_flagged(tmp_path: Path):
    (tmp_path / "Caddyfile").write_text(
        "example.com {\n"
        "  tls {\n"
        "    cipher_suites TLS_RSA_WITH_3DES_EDE_CBC_SHA TLS_AES_256_GCM_SHA384\n"
        "  }\n"
        "}\n"
    )
    found = await _run([tmp_path])
    assert len(found) == 1
    assert found[0].algorithm == "3DES"
    assert found[0].classification is Classification.SANGAT_TINGGI


@pytest.mark.asyncio
async def test_safe_caddyfile_emits_nothing(tmp_path: Path):
    (tmp_path / "Caddyfile").write_text(
        "example.com {\n"
        "  reverse_proxy localhost:8080\n"
        "}\n"
    )
    assert await _run([tmp_path]) == []


@pytest.mark.asyncio
async def test_json_config_weak_protocol_min_and_ciphers(tmp_path: Path):
    (tmp_path / "caddy.json").write_text(json.dumps({
        "apps": {"http": {"servers": {"srv0": {
            "tls_connection_policies": [{
                "protocol_min": "tls1.0",
                "cipher_suites": ["TLS_RSA_WITH_RC4_128_SHA"],
            }],
        }}}},
    }))
    found = await _run([tmp_path])
    assert {f.algorithm for f in found} == {"TLS1.0", "RC4"}
    assert all(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_invalid_json_is_ignored(tmp_path: Path):
    (tmp_path / "broken.json").write_text("{not valid json")
    assert await _run([tmp_path]) == []


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    probe = FsConfCaddy(roots=[tmp_path / "nope" / "Caddyfile"])
    assert await probe.applies(_ctx()) is False
