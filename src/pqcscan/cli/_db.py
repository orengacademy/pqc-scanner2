"""Shared `--db` handling: a SQLite path, or a full SQLAlchemy URL (postgresql://…)."""
from __future__ import annotations

from pathlib import Path

from pqcscan.util.paths import default_db_path


def db_arg(value: str | None) -> Path | str:
    """URL (contains "://") passes through untouched: Path() would collapse the "//"."""
    if value and "://" in value:
        return value
    return Path(value) if value else default_db_path()
