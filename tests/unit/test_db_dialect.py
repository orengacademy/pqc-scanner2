"""Proof that the verify workflow's Postgres job really runs on PostgreSQL: a mistyped or unset
PQCSCAN_TEST_DB_URL would otherwise fall back to SQLite and still pass.

Locally the test skips without PQCSCAN_TEST_DB_URL. CI sets PQCSCAN_REQUIRE_POSTGRES=1, and then a missing URL fails."""
import os

import pytest

from pqcscan.store.repo import Repo


def test_tmp_db_path_is_a_fresh_postgresql_database(tmp_db_path):
    if not os.environ.get("PQCSCAN_TEST_DB_URL"):
        if os.environ.get("PQCSCAN_REQUIRE_POSTGRES"):
            pytest.fail("PQCSCAN_REQUIRE_POSTGRES is set but PQCSCAN_TEST_DB_URL is not: the run would use SQLite")
        pytest.skip("PQCSCAN_TEST_DB_URL not set")
    repo = Repo(tmp_db_path)
    assert repo.engine.dialect.name == "postgresql"
    assert repo.engine.url.database.startswith("pqcscan_t_")
