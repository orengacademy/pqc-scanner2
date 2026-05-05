import json
import os
import subprocess
import sys
from pathlib import Path


def _run(*args, env=None):
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    full_env["PYTHONPATH"] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "src"
    )
    return subprocess.run(
        [sys.executable, "-m", "pqcscan", *args],
        capture_output=True, text=True, env=full_env,
    )


def test_scan_then_export_cbom(tmp_path: Path):
    db = tmp_path / "db.sqlite"
    env = {"PQCSCAN_DB_PATH": str(db)}

    p1 = _run("scan", "--json", env=env)
    assert p1.returncode in (0, 1), p1.stderr
    scan_id = json.loads(p1.stdout)["scan_id"]

    out = tmp_path / "cbom.json"
    p2 = _run(
        "export", "--scan", str(scan_id),
        "--format", "cbom", "-o", str(out), env=env,
    )
    assert p2.returncode == 0, p2.stderr
    assert out.exists()

    cbom = json.loads(out.read_text())
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"


def test_scan_then_export_pdf_technical(tmp_path: Path):
    import pytest
    pytest.importorskip("weasyprint")
    db = tmp_path / "db.sqlite"
    env = {"PQCSCAN_DB_PATH": str(db)}

    p1 = _run("scan", "--json", env=env)
    assert p1.returncode in (0, 1), p1.stderr
    scan_id = json.loads(p1.stdout)["scan_id"]

    out = tmp_path / "report.pdf"
    p2 = _run(
        "export", "--scan", str(scan_id),
        "--format", "pdf-tech", "-o", str(out), env=env,
    )
    assert p2.returncode == 0, p2.stderr
    assert out.exists()
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert len(data) > 1000
