from pathlib import Path

import pytest


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """A fresh on-disk SQLite path per test."""
    return tmp_path / "pqcscan-test.db"


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path
