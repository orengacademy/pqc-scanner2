"""Daemon lifecycle smoke test.

Spawns the daemon as a subprocess on a random port, polls each UI page
+ /api/health for HTTP 200, then SIGTERMs and asserts clean exit.
Catches regressions in:
- Daemon startup ordering (DB schema migrate -> bind -> uvicorn).
- UI route registration (all 6 core pages reachable).
- Graceful shutdown (no zombie process, exit within timeout).
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _free_tcp_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout_s: float = 15.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


def test_daemon_lifecycle_full(tmp_path: Path) -> None:
    port = _free_tcp_port()
    db = tmp_path / "lifecycle.db"
    proc = subprocess.Popen(
        [sys.executable, "-m", "pqcscan", "daemon",
         "--port", str(port), "--db", str(db)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        assert _wait_http(f"{base}/api/health"), "daemon did not become healthy in 15s"

        for path in ("/", "/scans", "/probes", "/frameworks", "/baselines", "/settings"):
            with urllib.request.urlopen(f"{base}{path}", timeout=5.0) as r:
                assert r.status == 200, f"{path} returned {r.status}"
                body = r.read()
                assert b"<title>" in body, f"{path} missing <title> tag"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise AssertionError("daemon did not exit within 10s of SIGTERM") from None

    assert proc.returncode in (0, -15, 143), f"unexpected exit code {proc.returncode}"
