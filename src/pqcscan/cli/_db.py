"""Shared `--db` handling: a SQLite path, or a full SQLAlchemy URL (postgresql://…)."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.engine import make_url

from pqcscan.util.paths import default_db_path


def db_arg(value: str | None) -> Path | str:
    """URL (contains "://") passes through untouched: Path() would collapse the "//"."""
    if value and "://" in value:
        return value
    return Path(value) if value else default_db_path()


def ensure_db_parent(db: Path | str) -> None:
    """Create the SQLite file's directory, for a path or a sqlite:/// URL; other URLs have none."""
    if isinstance(db, str):
        url = make_url(db)
        if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
            return
        db = Path(url.database)
    db.parent.mkdir(parents=True, exist_ok=True)
