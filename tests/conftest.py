from pathlib import Path

import pytest

from pqcscan.probes._registry import Registry


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """A fresh on-disk SQLite path per test."""
    return tmp_path / "pqcscan-test.db"


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def fast_registry() -> Registry:
    """Minimal one-probe Registry for integration tests that need a quick
    end-to-end scan completion. The full default_registry() runs 109 probes
    including ~30 network probes that hit their 30s timeout on CI runners
    with no reachable services, making scans take 5+ min."""
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    reg = Registry()
    reg.register(AuxClockCertValidity())
    return reg
