"""The wheel builds non-editably, as `pip install .` and `pip install git+…@sha` do, with every data file once.

Editable installs and PyInstaller never build the wheel, so a broken wheel config (a force-include of a directory the
package already ships: hatchling refuses the second copy) passed CI and failed only on a real soak droplet."""
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("hatchling")
REPO = Path(__file__).resolve().parents[2]
DATA = (
    "pqcscan/renderers/templates/bukukerja-template.xlsx",
    "pqcscan/renderers/templates/pdf_executive.html",
    "pqcscan/renderers/templates/pdf_technical.html",
    "pqcscan/ui/templates/base.html",
    "pqcscan/ui/templates/fleet.html",
    "pqcscan/ui/static/app.css",
    "pqcscan/ui/static/htmx-1.9.10.min.js",
    "pqcscan/ui/static/tailwind.min.css",
    "pqcscan/probes/_semgrep_rules/pqc-readiness.yaml",
)


def test_wheel_builds_with_each_data_file_once(tmp_path):
    r = subprocess.run([sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", str(tmp_path)],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]
    (wheel,) = tmp_path.glob("pqcscan-*.whl")
    names = Counter(zipfile.ZipFile(wheel).namelist())
    assert [n for n, c in names.items() if c > 1] == []
    assert {p: names[p] for p in DATA} == dict.fromkeys(DATA, 1)
