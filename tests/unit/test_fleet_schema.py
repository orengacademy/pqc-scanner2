"""Fleet schema: hosts table, scans.host_id / scan_uuid, and in-place upgrade of pre-fleet DBs."""
import sqlite3
import uuid
from pathlib import Path

from sqlalchemy import inspect

from pqcscan.store.repo import Repo


def test_new_db_has_hosts_table_and_scan_columns(tmp_db_path: Path):
    repo = Repo(tmp_db_path); repo.init_schema()
    insp = inspect(repo.engine)
    assert "hosts" in insp.get_table_names()
    scan_cols = {c["name"] for c in insp.get_columns("scans")}
    assert {"host_id", "scan_uuid"} <= scan_cols
    host_cols = {c["name"] for c in insp.get_columns("hosts")}
    assert {"machine_id", "hostname", "os", "labels", "agent_version",
            "first_seen", "last_seen", "token_hash", "revoked"} <= host_cols


def test_create_scan_gets_a_uuid(tmp_db_path: Path):
    repo = Repo(tmp_db_path); repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    s = repo.get_scan(sid)
    assert s is not None and s.scan_uuid and uuid.UUID(s.scan_uuid)
    sid2 = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    assert repo.get_scan(sid2).scan_uuid != s.scan_uuid


def test_pre_fleet_db_is_upgraded_in_place(tmp_path: Path):
    # A 0.9.x DB: scans table without host_id / scan_uuid, no hosts table.
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE scans (id INTEGER PRIMARY KEY, started_at DATETIME, finished_at DATETIME,
            host_fingerprint VARCHAR(128), mode VARCHAR(8), status VARCHAR(16), label VARCHAR(128),
            probe_versions JSON, tool_versions JSON);
        INSERT INTO scans (started_at, mode, status, probe_versions, tool_versions)
            VALUES ('2026-01-01 00:00:00', 'user', 'done', '{}', '{}');
    """)
    con.commit(); con.close()
    repo = Repo(db); repo.init_schema()
    scan_cols = {c["name"] for c in inspect(repo.engine).get_columns("scans")}
    assert {"host_id", "scan_uuid"} <= scan_cols
    assert repo.get_scan(1).scan_uuid is None          # old rows keep NULL
    repo.init_schema()                                  # idempotent second run
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    assert repo.get_scan(sid).scan_uuid
