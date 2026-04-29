from __future__ import annotations

from sqlalchemy import Engine

from pqcscan.store.schema import Base


def apply(engine: Engine) -> None:
    """Create all tables. Idempotent."""
    Base.metadata.create_all(engine)
