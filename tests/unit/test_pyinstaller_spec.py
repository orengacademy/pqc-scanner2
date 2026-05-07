"""Smoke tests for build/pyinstaller.spec.

We validate Python syntax + presence of critical bundling rules. We do
NOT invoke PyInstaller here — that's slow and requires the package to
be installed.
"""
import os
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SPEC = _REPO_ROOT / "build" / "pyinstaller.spec"


def test_spec_file_exists():
    assert _SPEC.is_file(), f"missing {_SPEC}"


def test_spec_is_valid_python():
    """compile() catches syntax errors without needing PyInstaller globals."""
    src = _SPEC.read_text(encoding="utf-8")
    compile(src, str(_SPEC), "exec")


def test_spec_references_cli_entry():
    src = _SPEC.read_text(encoding="utf-8")
    assert '"pqcscan" / "cli" / "main.py"' in src


def test_spec_bundles_critical_data():
    """All runtime-required data dirs must be in the DATAS list."""
    src = _SPEC.read_text(encoding="utf-8")
    for needed in (
        '"pqcscan" / "ui" / "templates"',
        '"pqcscan" / "ui" / "static"',
        '"pqcscan" / "compliance" / "frameworks"',
        '"pqcscan" / "renderers" / "templates"',
        '"pqcscan" / "probes" / "_semgrep_rules"',
    ):
        assert needed in src, f"spec must bundle {needed}"


def test_spec_includes_dynamic_imports():
    """Probe modules + renderer deps must be listed as hidden imports."""
    src = _SPEC.read_text(encoding="utf-8")
    for needed in (
        "pqcscan.probes._registry",
        "pqcscan.compliance.engine",
        "pqcscan.runner.runner",
        "weasyprint",
        "openpyxl",
        "cyclonedx",
        "multipart",
    ):
        assert needed in src, f"spec must hidden-import {needed}"


def test_build_script_exists_and_executable():
    script = _REPO_ROOT / "scripts" / "build-binary.sh"
    assert script.is_file(), f"missing {script}"
    if os.name != "nt":
        mode = script.stat().st_mode
        assert mode & 0o100, f"{script} is not executable"


@pytest.mark.parametrize(
    "rel_path",
    [
        "src/pqcscan/cli/main.py",
        "src/pqcscan/ui/templates/base.html",
        "src/pqcscan/compliance/frameworks/bukukerja.yaml",
        "src/pqcscan/renderers/templates",
    ],
)
def test_spec_referenced_paths_exist_on_disk(rel_path):
    """Sanity-check that the paths the spec promises to bundle are real."""
    p = _REPO_ROOT / rel_path
    assert p.exists(), f"spec references missing path: {p}"
