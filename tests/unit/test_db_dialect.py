"""Proof that the verify workflow's Postgres job really runs on PostgreSQL: a mistyped or unset
PQCSCAN_TEST_DB_URL would otherwise fall back to SQLite and still pass."""
import os

import pytest

from pqcscan.store.repo import Repo


@pytest.mark.skipif(not os.environ.get("PQCSCAN_TEST_DB_URL"), reason="PQCSCAN_TEST_DB_URL not set")
def test_tmp_db_path_is_a_fresh_postgresql_database(tmp_db_path):
    repo = Repo(tmp_db_path)
    assert repo.engine.dialect.name == "postgresql"
    assert repo.engine.url.database.startswith("pqcscan_t_")
