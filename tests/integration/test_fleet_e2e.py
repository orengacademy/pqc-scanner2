"""Two hosts scan with --report-to against a live daemon; the fleet shows both and exports them."""
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from pqcscan.daemon.app import create_app

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def daemon(tmp_path, fast_registry):
    port = _free_port()
    app = create_app(db_path=tmp_path / "fleet.db", registry=fast_registry, enroll_token="E")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/api/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", tmp_path / "fleet.db"
    server.should_exit = True
    t.join(timeout=5)


def _host_scan(url: str, tmp_path: Path, name: str, machine_id: str) -> dict:
    env = {**os.environ, "PYTHONPATH": SRC, "PQCSCAN_TEST_MACHINE_ID": machine_id}
    scan_dir = tmp_path / name
    scan_dir.mkdir()
    p = subprocess.run([sys.executable, "-m", "pqcscan", "scan", "--json", "--fail-on", "none",
                        "--db", str(tmp_path / f"{name}.db"), "--path", str(scan_dir),
                        "--report-to", url, "--enroll-token", "E", "--labels", f"host={name}",
                        "--state-dir", str(tmp_path / f"{name}-state")],
                       capture_output=True, text=True, env=env, timeout=600)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_two_hosts_report_and_fleet_exports(daemon, tmp_path):
    url, db = daemon
    a = _host_scan(url, tmp_path, "web01", "m-web01")
    b = _host_scan(url, tmp_path, "web02", "m-web02")
    assert a["report"]["stored_findings"] > 0 and b["report"]["stored_findings"] > 0
    fleet = httpx.get(f"{url}/api/fleet").json()
    assert sorted(h["labels"]["host"] for h in fleet) == ["web01", "web02"]
    cbom = httpx.get(f"{url}/api/scans/fleet/export/cbom").json()
    assert cbom["bomFormat"] == "CycloneDX"
    out = subprocess.run([sys.executable, "-m", "pqcscan", "fleet", "summary", "--db", str(db), "--json"],
                         capture_output=True, text=True, env={**os.environ, "PYTHONPATH": SRC})
    assert len(json.loads(out.stdout)) == 2
