"""Smoke test for .github/workflows/release.yml.

We don't run GitHub Actions locally; this test just validates that
the YAML parses, declares the right trigger and matrix, and references
the build artefacts that actually exist on disk.
"""
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"


@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def test_workflow_exists():
    assert _WORKFLOW.is_file(), f"missing {_WORKFLOW}"


def test_triggers_on_version_tags(doc):
    # PyYAML 1.1 parses bareword 'on' as Python True; accept either form.
    on = doc.get("on") or doc.get(True) or {}
    assert "push" in on
    assert "v*" in on["push"]["tags"]
    assert "workflow_dispatch" in on


def test_matrix_covers_all_release_targets(doc):
    matrix = doc["jobs"]["build"]["strategy"]["matrix"]["include"]
    oses = {entry["os"] for entry in matrix}
    assert oses == {"ubuntu-latest", "macos-latest", "macos-13", "windows-latest"}
    suffixes = {entry["asset_suffix"] for entry in matrix}
    assert suffixes == {"linux-x86_64", "macos-arm64", "macos-x86_64", "windows-x86_64.exe"}


def test_unix_jobs_invoke_build_script():
    src = _WORKFLOW.read_text(encoding="utf-8")
    assert "bash scripts/build-binary.sh" in src


def test_windows_job_invokes_pyinstaller_directly():
    src = _WORKFLOW.read_text(encoding="utf-8")
    # Windows runners don't have bash by default, so we drive pyinstaller
    # straight from PowerShell.
    assert "pyinstaller --clean --noconfirm" in src
    assert "build/pyinstaller.spec" in src


def test_release_job_runs_only_on_tag(doc):
    rel = doc["jobs"]["release"]
    assert rel["if"] == "startsWith(github.ref, 'refs/tags/v')"
    assert rel["needs"] == "build"


def test_workflow_has_contents_write_permission(doc):
    """Required so softprops/action-gh-release can attach assets."""
    assert doc["permissions"]["contents"] == "write"


def test_referenced_build_artifacts_exist():
    """Spec + script must already be on disk for the workflow to work."""
    assert (_REPO_ROOT / "build" / "pyinstaller.spec").is_file()
    assert (_REPO_ROOT / "scripts" / "build-binary.sh").is_file()
