"""Resolve external FOSS tools (syft, grype, semgrep, …) at runtime.

Search order (first hit wins):
1. ``$PQCSCAN_OFFLINE_PACK`` env var, if set — points at a directory
   that contains the tool binaries. Useful for users who download the
   offline pack separately and don't want to rebuild the binary.
2. PyInstaller's ``sys._MEIPASS / 'tools'`` — populated when the
   pqcscan binary was built with the offline pack bundled in
   (``tools/`` directory present at build time).
3. ``shutil.which(name)`` — picks up tools installed on the host
   ``$PATH``. Default fallback for development.

Returns ``None`` if the tool isn't found in any location; probes are
responsible for emitting an INFO finding when the tool is missing
(rather than crashing).
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

_ENV_OVERRIDE = "PQCSCAN_OFFLINE_PACK"


def _meipass_root() -> Path | None:
    """Return PyInstaller's runtime extraction dir, or None at dev time."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return None


def _candidate(directory: Path, name: str) -> Path | None:
    """Return ``directory / name`` (or ``name.exe`` on Windows) if executable."""
    candidates = [directory / name]
    if sys.platform == "win32":
        candidates.append(directory / f"{name}.exe")
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def resolve_tool(name: str) -> Path | None:
    """Locate a FOSS tool binary, returning the absolute path or None.

    Examples:
        >>> resolve_tool("syft")     # /opt/pqcscan/tools/syft, or /usr/local/bin/syft
        >>> resolve_tool("grype")    # likewise
        >>> resolve_tool("nonexistent")  # None
    """
    # 1. Environment override.
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        hit = _candidate(Path(override), name)
        if hit is not None:
            return hit

    # 2. PyInstaller MEIPASS bundle.
    mei = _meipass_root()
    if mei is not None:
        hit = _candidate(mei / "tools", name)
        if hit is not None:
            return hit

    # 3. System PATH.
    which = shutil.which(name)
    if which:
        return Path(which)

    return None


def resolve_or_none(explicit: str | None, default_name: str) -> Path | None:
    """Validate an explicit binary path, or fall back to resolve_tool().

    Probes accept an optional ``<tool>_bin`` constructor argument that
    overrides auto-detection. This helper centralises the validation:

    - If ``explicit`` is set: return it as a Path iff it exists and is
      executable, else None (NOT a fallthrough — the caller asked for
      that specific binary).
    - If ``explicit`` is None: delegate to ``resolve_tool(default_name)``.

    Matches the original ``shutil.which("/no/such/path") -> None``
    semantics so a missing explicit path doesn't silently use a
    different binary from PATH.
    """
    if explicit:
        p = Path(explicit)
        if p.is_file() and os.access(p, os.X_OK):
            return p
        return None
    return resolve_tool(default_name)
