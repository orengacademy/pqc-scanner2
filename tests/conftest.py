import os
import uuid
from pathlib import Path

import pytest

from pqcscan.probes._registry import Registry


@pytest.fixture
def tmp_db_path(tmp_path: Path):
    """A fresh store per test: an on-disk SQLite path, or, when PQCSCAN_TEST_DB_URL is set (CI verify
    workflow, `postgresql+psycopg://user:pw@host:port/postgres`), a URL to a database created for this test
    on that server and dropped afterwards."""
    admin_url = os.environ.get("PQCSCAN_TEST_DB_URL")
    if not admin_url:
        yield tmp_path / "pqcscan-test.db"
        return
    import psycopg
    from sqlalchemy.engine import make_url

    base = make_url(admin_url)
    name = f"pqcscan_t_{uuid.uuid4().hex}"
    dsn = base.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def fast_registry() -> Registry:
    """Minimal one-probe Registry for integration tests that need a quick
    end-to-end scan completion. The full default_registry() runs 180 probes
    including ~40 network probes that hit their 30s timeout on CI runners
    with no reachable services, making scans take 5+ min."""
    from pqcscan.probes.aux_clock_cert_validity import AuxClockCertValidity
    reg = Registry()
    reg.register(AuxClockCertValidity())
    return reg
