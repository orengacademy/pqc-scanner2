from pqcscan.store.repo import Repo


def test_sqlite_uses_wal_and_busy_timeout(tmp_db_path):
    """Concurrent background-thread writers (daemon scans) rely on WAL +
    busy_timeout instead of default SQLite locking, which raises
    'database is locked' under writer contention."""
    repo = Repo(tmp_db_path)
    repo.init_schema()
    with repo.engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000
