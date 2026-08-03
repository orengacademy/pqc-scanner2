"""Time helper.

``datetime.utcnow()`` is deprecated (Python 3.12+). We keep storing *naive*
UTC timestamps — the SQLite columns, the CBOM/report formatters and every
existing comparison assume tz-naive values — so this returns an aware-UTC now
stripped back to naive, preserving behaviour without the deprecation.
"""
from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Current UTC time as a tz-naive datetime (drop-in for datetime.utcnow)."""
    return datetime.now(UTC).replace(tzinfo=None)
