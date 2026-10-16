from __future__ import annotations

from sqlalchemy import Engine, inspect, text

from pqcscan.store.schema import Base

# Columns added after a table first shipped. create_all() never alters an
# existing table, so each (table, column, DDL type) here is applied with an
# idempotent ALTER TABLE on DBs created before the column existed.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("scans", "host_id", "INTEGER"),
    ("scans", "scan_uuid", "VARCHAR(36)"),
)


def apply(engine: Engine) -> None:
    """Create all tables, then add any columns missing from pre-existing tables. Idempotent."""
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl_type in _ADDED_COLUMNS:
            present = {c["name"] for c in insp.get_columns(table)}
            if column not in present:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_scans_scan_uuid ON scans (scan_uuid)"
        ))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_host_id ON scans (host_id)"))
