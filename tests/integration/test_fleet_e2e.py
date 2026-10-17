"""Two hosts scan with --report-to against a live daemon; the fleet shows both and exports them."""
import datetime
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
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from pqcscan.daemon.app import create_app

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def daemon(tmp_path, fast_registry):
    # fast_registry only serves the daemon's own /api/scans; the host scans here run in subprocesses.
    port = _free_port()
    app = create_app(db_path=tmp_path / "fleet.db", registry=fast_registry, enroll_token="E")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if not t.is_alive():
                pytest.fail("uvicorn thread died during startup")
            try:
                if httpx.get(f"http://127.0.0.1:{port}/api/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        else:
            pytest.fail("daemon did not become healthy")
        yield f"http://127.0.0.1:{port}", tmp_path / "fleet.db"
    finally:
        server.should_exit = True
        t.join(timeout=5)
        assert not t.is_alive(), "uvicorn thread did not stop"


def _weak_cert_pem() -> bytes:
    """Self-signed RSA-1024 cert, 1 day validity, so fs.cert.x509 fires regardless of the CI box."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "weak-rsa1024.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.PEM)


def _host_scan(url: str, tmp_path: Path, name: str, machine_id: str) -> dict:
    env = {**os.environ, "PYTHONPATH": SRC, "PQCSCAN_TEST_MACHINE_ID": machine_id}
    scan_dir = tmp_path / name
    scan_dir.mkdir()
    (scan_dir / "server.pem").write_bytes(_weak_cert_pem())
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
    # export builds a temporary rollup; it takes ~5s on this box, so the 5s httpx default is too tight
    cbom = httpx.get(f"{url}/api/scans/fleet/export/cbom", timeout=60).json()
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["components"], "fleet CBOM has no components"
    props = [p for c in cbom["components"] for p in c.get("properties", [])]
    assert {p["value"] for p in props if p["name"] == "pqcscan:machine_id"} == {"m-web01", "m-web02"}
    out = subprocess.run([sys.executable, "-m", "pqcscan", "fleet", "summary", "--db", str(db), "--json"],
                         capture_output=True, text=True, env={**os.environ, "PYTHONPATH": SRC})
    assert out.returncode == 0, out.stderr
    assert len(json.loads(out.stdout)) == 2
