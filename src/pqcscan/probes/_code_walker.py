"""Shared filesystem walker for source-code probes."""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path


_EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "vendor", "dist", "build", "target", ".gradle", ".m2",
    ".cargo", ".bundle",
}


def walk_source(roots: Iterable[Path], suffixes: tuple[str, ...]) -> Iterator[Path]:
    """Yield source files under each root with one of `suffixes`, skipping
    common dependency / build directories."""
    suffix_set = {s.lower() for s in suffixes}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in suffix_set:
                continue
            if any(part in _EXCLUDE_DIRS for part in path.parts):
                continue
            yield path
