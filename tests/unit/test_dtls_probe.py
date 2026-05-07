from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._dtls_probe import run_dtls_probe

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl binary not on PATH"
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def dtls_server(tmp_path: Path):
    cert = tmp_path / "test.pem"
    key = tmp_path / "test.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-subj", "/CN=test-dtls",
        ],
        check=True, capture_output=True,
    )
    port = _free_port()
    proc = subprocess.Popen(
        [
            "openssl", "s_server", "-dtls1_2",
            "-cert", str(cert), "-key", str(key),
            "-accept", str(port), "-quiet",
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)
    yield "127.0.0.1", port
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.mark.asyncio
async def test_run_dtls_probe_emits_finding(dtls_server):
    host, port = dtls_server
    findings: list[Finding] = []

    def emit(f: Finding) -> None:
        findings.append(f)

    await run_dtls_probe(
        host=host, port=port, version="1.2",
        probe_id="net.dtls.test", emit=emit,
    )

    assert any(f.probe_id == "net.dtls.test" for f in findings), \
        f"expected at least one finding from net.dtls.test, got {findings!r}"
