from __future__ import annotations

import os
import sys
from pathlib import Path


def default_db_path() -> Path:
    """Return OS-appropriate default DB path; respect PQCSCAN_DB_PATH env."""
    if env := os.environ.get("PQCSCAN_DB_PATH"):
        return Path(env)
    if sys.platform == "win32":
        return (
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            / "pqcscan"
            / "pqcscan.db"
        )
    if sys.platform == "darwin":
        return Path("/Library/Application Support/pqcscan/pqcscan.db")
    return Path("/var/lib/pqcscan/pqcscan.db")
