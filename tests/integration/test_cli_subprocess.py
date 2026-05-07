"""Subprocess-level CLI smoke tests.

Catches regressions where the in-process Click runner passes but the
shipped entry-point silently exits (the v0.2.0-v0.6.0 PyInstaller bug
where `cli/main.py` declared the click group but never invoked it).

Tests both invocation styles:
- `python -m pqcscan.cli.main` — what PyInstaller binaries hit
- `python -m pqcscan`          — what users hit via __main__.py
"""
from __future__ import annotations

import subprocess
import sys


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_cli_main_module_help_emits_usage() -> None:
    """python -m pqcscan.cli.main --help prints Click help (not silent)."""
    r = _run(["-m", "pqcscan.cli.main", "--help"])
    assert r.returncode == 0, f"non-zero exit: stderr={r.stderr!r}"
    assert "Usage:" in r.stdout, f"no Usage line; stdout={r.stdout!r}"
    assert "Post-Quantum Cryptography" in r.stdout
    for cmd in ("scan", "scans", "daemon", "export", "version"):
        assert cmd in r.stdout, f"command '{cmd}' missing from help"


def test_cli_main_module_version() -> None:
    r = _run(["-m", "pqcscan.cli.main", "version"])
    assert r.returncode == 0, f"non-zero exit: stderr={r.stderr!r}"
    assert "pqcscan" in r.stdout.lower()


def test_pqcscan_module_help_emits_usage() -> None:
    """python -m pqcscan --help (via __main__.py) prints Click help."""
    r = _run(["-m", "pqcscan", "--help"])
    assert r.returncode == 0, f"non-zero exit: stderr={r.stderr!r}"
    assert "Usage:" in r.stdout
    assert "Post-Quantum Cryptography" in r.stdout


def test_pqcscan_module_no_args_emits_help() -> None:
    """Running without args prints help (Click default group behavior)."""
    r = _run(["-m", "pqcscan"])
    assert "Usage:" in r.stdout or "Usage:" in r.stderr
