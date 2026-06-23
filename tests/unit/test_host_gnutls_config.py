"""Tests for host.gnutls.config (GnuTLS system priority configuration)."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.host_gnutls_config import HostGnutlsConfig


def _ctx() -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set())


def _write(tmp_path: Path, value: str) -> Path:
    cfg = tmp_path / "gnutls.config"
    cfg.write_text(value)
    return cfg


async def _run(cfg: Path) -> list:
    found: list = []
    probe = HostGnutlsConfig(config_paths=[cfg])
    await probe.run(_ctx(), emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_weak_priority_flags_legacy_and_weak(tmp_path: Path):
    cfg = _write(tmp_path, "NONE:+VERS-TLS1.0:+ARCFOUR-128:+3DES-CBC:+MD5\n")
    found = await _run(cfg)
    algos = {f.algorithm for f in found}
    assert "gnutls/legacy-protocols" in algos
    assert "gnutls/weak-primitives" in algos
    legacy = next(f for f in found if f.algorithm == "gnutls/legacy-protocols")
    assert legacy.classification is Classification.TINGGI
    assert legacy.severity is Severity.HIGH
    weak = next(f for f in found if f.algorithm == "gnutls/weak-primitives")
    assert weak.classification is Classification.TINGGI
    assert weak.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_pqc_group_present_no_pqc_finding(tmp_path: Path):
    cfg = _write(tmp_path, "SECURE256:+GROUP-X25519-MLKEM768\n")
    found = await _run(cfg)
    algos = {f.algorithm for f in found}
    assert "gnutls/no-pqc-groups" not in algos
    assert "gnutls/legacy-protocols" not in algos
    assert "gnutls/weak-primitives" not in algos


@pytest.mark.asyncio
async def test_modern_classical_flags_only_no_pqc(tmp_path: Path):
    # Modern classical: no legacy protocols, no weak primitives, but no PQC group.
    cfg = _write(tmp_path, "SECURE256:+VERS-TLS1.3\n")
    found = await _run(cfg)
    assert len(found) == 1
    assert found[0].algorithm == "gnutls/no-pqc-groups"
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED
    assert found[0].evidence["note"] == "no PQC groups in GnuTLS priority"


@pytest.mark.asyncio
async def test_normal_without_explicit_legacy_only_no_pqc(tmp_path: Path):
    cfg = _write(tmp_path, "NORMAL\n")
    found = await _run(cfg)
    algos = {f.algorithm for f in found}
    assert algos == {"gnutls/no-pqc-groups"}


@pytest.mark.asyncio
async def test_comments_ignored(tmp_path: Path):
    cfg = _write(tmp_path, "# +VERS-SSL3.0 +ARCFOUR-128 in a comment\nSECURE256:+GROUP-KYBER768\n")
    found = await _run(cfg)
    assert found == []


@pytest.mark.asyncio
async def test_absent_emits_nothing(tmp_path: Path):
    cfg = tmp_path / "gnutls.config"  # not written
    found = await _run(cfg)
    assert found == []


@pytest.mark.asyncio
async def test_applies_false_when_absent(tmp_path: Path):
    cfg = tmp_path / "gnutls.config"
    probe = HostGnutlsConfig(config_paths=[cfg])
    assert await probe.applies(_ctx()) is False


@pytest.mark.asyncio
async def test_applies_true_when_present(tmp_path: Path):
    cfg = _write(tmp_path, "NORMAL\n")
    probe = HostGnutlsConfig(config_paths=[cfg])
    assert await probe.applies(_ctx()) is True
