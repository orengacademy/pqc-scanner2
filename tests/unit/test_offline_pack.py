"""Tests for pqcscan.util.offline_pack.resolve_tool()."""
import stat
import sys
from pathlib import Path

from pqcscan.util.offline_pack import resolve_tool


def _make_fake_binary(parent: Path, name: str) -> Path:
    """Create a tmp executable file that resolve_tool() will accept."""
    parent.mkdir(parents=True, exist_ok=True)
    path = parent / name
    path.write_text("#!/bin/sh\necho fake\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def test_returns_none_when_tool_missing(monkeypatch):
    monkeypatch.delenv("PQCSCAN_OFFLINE_PACK", raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", "/non-existent-meipass", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert resolve_tool("pqcscan-no-such-tool") is None


def test_env_override_wins(monkeypatch, tmp_path):
    """PQCSCAN_OFFLINE_PACK overrides MEIPASS and PATH."""
    bin_path = _make_fake_binary(tmp_path / "override", "syft")
    monkeypatch.setenv("PQCSCAN_OFFLINE_PACK", str(tmp_path / "override"))
    monkeypatch.setattr(sys, "_MEIPASS", "/non-existent-meipass", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/syft")
    found = resolve_tool("syft")
    assert found == bin_path


def test_meipass_used_when_no_env_override(monkeypatch, tmp_path):
    """At PyInstaller runtime _MEIPASS / 'tools' is the second-priority hit."""
    monkeypatch.delenv("PQCSCAN_OFFLINE_PACK", raising=False)
    bin_path = _make_fake_binary(tmp_path / "tools", "grype")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/grype")
    found = resolve_tool("grype")
    assert found == bin_path


def test_falls_back_to_system_path(monkeypatch, tmp_path):
    """When neither env nor MEIPASS yields a hit, shutil.which is used."""
    monkeypatch.delenv("PQCSCAN_OFFLINE_PACK", raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", "/non-existent-meipass", raising=False)
    fake = _make_fake_binary(tmp_path, "semgrep")
    monkeypatch.setattr("shutil.which",
                        lambda name: str(fake) if name == "semgrep" else None)
    found = resolve_tool("semgrep")
    assert found == Path(str(fake))


def test_env_override_dir_without_tool_falls_through(monkeypatch, tmp_path):
    """If override dir exists but doesn't contain the tool, fall through."""
    (tmp_path / "empty-override").mkdir()
    monkeypatch.setenv("PQCSCAN_OFFLINE_PACK", str(tmp_path / "empty-override"))
    monkeypatch.setattr(sys, "_MEIPASS", "/non-existent-meipass", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/syft")
    found = resolve_tool("syft")
    assert found == Path("/usr/bin/syft")


def test_non_executable_in_override_is_ignored(monkeypatch, tmp_path):
    """Non-executable file in override dir must not be returned."""
    not_exec = tmp_path / "override" / "syft"
    not_exec.parent.mkdir()
    not_exec.write_text("not a real binary")
    monkeypatch.setenv("PQCSCAN_OFFLINE_PACK", str(tmp_path / "override"))
    monkeypatch.setattr(sys, "_MEIPASS", "/non-existent-meipass", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/syft")
    found = resolve_tool("syft")
    assert found == Path("/usr/bin/syft")
