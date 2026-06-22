import json
import os
import subprocess
import sys

from pqcscan import __version__


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


def test_version():
    p = _run("version")
    assert p.returncode == 0, p.stderr
    assert __version__ in p.stdout


def test_help():
    p = _run("--help")
    assert p.returncode == 0
    assert "Usage:" in p.stdout
    assert "scan" in p.stdout
    assert "daemon" in p.stdout
    assert "export" in p.stdout


def test_scan_in_process_writes_to_db(tmp_path):
    db = tmp_path / "test.db"
    p = _run("scan", "--json", env={"PQCSCAN_DB_PATH": str(db)})
    assert p.returncode in (0, 1), p.stderr
    out = json.loads(p.stdout)
    assert "scan_id" in out
    assert isinstance(out["finding_count"], int)
