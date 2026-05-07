# Plan H Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sharpen pqcscan to PQC-only focus (drop 11 YAGNI probes), add UDP + DTLS scan foundation, and add a 15-probe OT/ICS T4 family for NCII coverage.

**Architecture:** Three additive sub-plans (H.1 trim, H.2 UDP+DTLS, H.3 OT 7+4+4) layered on the existing `Probe` ABC + `default_registry()` + `ProbeRunner` + Jinja+HTMX UI + 10-framework YAML compliance engine. No schema migrations. No new top-level subsystems. Each sub-batch ships its own version tag and is independently revertable.

**Tech Stack:** Python 3.11, asyncio, FastAPI, Jinja2, HTMX, SQLAlchemy + SQLite, click, openssl (shell-out for DTLS), pytest + pytest-asyncio, ruff, mypy. Project source under `src/pqcscan/`, tests under `tests/`.

**Spec:** `docs/superpowers/specs/2026-05-07-pqcscan-plan-h-pqc-scope-and-ot-coverage-design.md`

---

## Pre-flight

### Task 0.1: Branch + baseline test sweep

**Files:**
- Modify: working tree (no file edits)

- [ ] **Step 1: Confirm clean working tree**

```bash
cd pqc-scanner2
git status
```

Expected: nothing to commit, working tree clean. If untracked files exist (e.g. `.claude/`, screenshot artifacts), commit, stash, or `.gitignore` first — do not proceed with dirty tree.

- [ ] **Step 2: Create feature branch**

```bash
git checkout -b plan-h
```

- [ ] **Step 3: Run baseline test suite**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
```

Expected: ~365+ tests pass. Record exact count for delta tracking after H.1 trim.

- [ ] **Step 4: Record baseline probe count**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"
```

Expected: `109`. Record number for delta tracking.

---

## Phase 1 — H.1: YAGNI trim (target tag v0.2.0)

Eleven probes drop. Tests for those probes drop. Registry shrinks from 109 → 98.

### Task 1.1: Delete CVE family — 7 probes

**Files:**
- Delete: `src/pqcscan/probes/cve_grype.py`
- Delete: `src/pqcscan/probes/cve_trivy_fs.py`
- Delete: `src/pqcscan/probes/cve_pip_audit.py`
- Delete: `src/pqcscan/probes/cve_npm_audit.py`
- Delete: `src/pqcscan/probes/cve_cargo_audit.py`
- Delete: `src/pqcscan/probes/cve_govulncheck.py`
- Delete: `src/pqcscan/probes/cve_osv_offline.py`
- Delete: `tests/probes/test_cve_*.py` (≈7 files)

- [ ] **Step 1: Verify each file exists before deletion**

```bash
for f in cve_grype cve_trivy_fs cve_pip_audit cve_npm_audit cve_cargo_audit cve_govulncheck cve_osv_offline; do
  test -f "src/pqcscan/probes/${f}.py" && echo "OK: src/pqcscan/probes/${f}.py" || echo "MISSING: ${f}"
done
```

Expected: 7 OK lines.

- [ ] **Step 2: Delete probe source files**

```bash
git rm src/pqcscan/probes/cve_grype.py \
       src/pqcscan/probes/cve_trivy_fs.py \
       src/pqcscan/probes/cve_pip_audit.py \
       src/pqcscan/probes/cve_npm_audit.py \
       src/pqcscan/probes/cve_cargo_audit.py \
       src/pqcscan/probes/cve_govulncheck.py \
       src/pqcscan/probes/cve_osv_offline.py
```

- [ ] **Step 3: Delete test files (only those that exist)**

```bash
for f in test_cve_grype test_cve_trivy_fs test_cve_pip_audit test_cve_npm_audit test_cve_cargo_audit test_cve_govulncheck test_cve_osv_offline; do
  if [ -f "tests/probes/${f}.py" ]; then
    git rm "tests/probes/${f}.py"
  fi
done
```

- [ ] **Step 4: Commit**

```bash
git commit -m "chore(probes): drop CVE family — out of PQC scope (Plan H.1)"
```

### Task 1.2: Delete secrets gitleaks probe

**Files:**
- Delete: `src/pqcscan/probes/secrets_gitleaks.py`
- Delete: `tests/probes/test_secrets_gitleaks.py` (if present)

- [ ] **Step 1: Delete source + test**

```bash
git rm src/pqcscan/probes/secrets_gitleaks.py
test -f tests/probes/test_secrets_gitleaks.py && git rm tests/probes/test_secrets_gitleaks.py
```

- [ ] **Step 2: Commit**

```bash
git commit -m "chore(probes): drop secrets.gitleaks — out of PQC scope (Plan H.1)"
```

### Task 1.3: Delete dotenv secrets probe

**Files:**
- Delete: `src/pqcscan/probes/app_dotenv_secrets.py`
- Delete: `tests/probes/test_app_dotenv_secrets.py` (if present)

- [ ] **Step 1: Delete source + test**

```bash
git rm src/pqcscan/probes/app_dotenv_secrets.py
test -f tests/probes/test_app_dotenv_secrets.py && git rm tests/probes/test_app_dotenv_secrets.py
```

- [ ] **Step 2: Commit**

```bash
git commit -m "chore(probes): drop app.dotenv_secrets — out of PQC scope (Plan H.1)"
```

### Task 1.4: Delete lynis + bandit probes

**Files:**
- Delete: `src/pqcscan/probes/host_lynis.py`
- Delete: `src/pqcscan/probes/code_bandit.py`
- Delete: `tests/probes/test_host_lynis.py` (if present)
- Delete: `tests/probes/test_code_bandit.py` (if present)

- [ ] **Step 1: Delete sources + tests**

```bash
git rm src/pqcscan/probes/host_lynis.py src/pqcscan/probes/code_bandit.py
test -f tests/probes/test_host_lynis.py && git rm tests/probes/test_host_lynis.py
test -f tests/probes/test_code_bandit.py && git rm tests/probes/test_code_bandit.py
```

- [ ] **Step 2: Commit**

```bash
git commit -m "chore(probes): drop host.lynis + code.bandit — out of PQC scope (Plan H.1)"
```

### Task 1.5: Trim default_registry()

**Files:**
- Modify: `src/pqcscan/probes/_registry.py`

- [ ] **Step 1: Read current registry to find probe instantiations**

```bash
grep -n "cve_grype\|cve_trivy_fs\|cve_pip_audit\|cve_npm_audit\|cve_cargo_audit\|cve_govulncheck\|cve_osv_offline\|secrets_gitleaks\|app_dotenv_secrets\|host_lynis\|code_bandit" src/pqcscan/probes/_registry.py
```

Expected: 11 import lines (or grouped imports) + 11 instantiation lines (or fewer if grouped).

- [ ] **Step 2: Remove the imports + instantiations**

For each dropped probe `Foo`:

```python
# Top-of-file import — DELETE:
from pqcscan.probes.cve_grype import CveGrype

# Inside default_registry() body — DELETE:
reg.add(CveGrype())
```

Repeat for all 11. The exact line numbers depend on the file's current shape — agent must read the file and remove each affected import line and registry-add line.

- [ ] **Step 3: Verify count**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"
```

Expected: `98`.

- [ ] **Step 4: Run test suite**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/_registry.py
git commit -m "refactor(registry): trim default_registry to 98 probes (Plan H.1)"
```

### Task 1.6: Trim offline-pack fetch script

**Files:**
- Modify: `scripts/fetch-offline-tools.sh`

- [ ] **Step 1: Read current script**

```bash
cat scripts/fetch-offline-tools.sh | head -150
```

Identify blocks that download `grype`, `trivy`, `pip-audit`, `npm`, `cargo-audit`, `govulncheck`, `lynis`, `bandit`, `gitleaks`. Each tool typically has its own `download_X()` function or `case` branch.

- [ ] **Step 2: Delete each block**

For each tool, remove:
- Its `download_<tool>()` function if any
- Its invocation in the main flow
- Any `usage` / `help` mention

Keep: `syft`, `semgrep`, `testssl`, `sslyze`, `nmap`.

- [ ] **Step 3: Smoke-run the script (help/dry-run mode)**

```bash
bash scripts/fetch-offline-tools.sh --help 2>&1 | head -20
```

Expected: usage message shows only the 5 retained tools; no error referencing removed tools.

- [ ] **Step 4: Commit**

```bash
git add scripts/fetch-offline-tools.sh
git commit -m "chore(offline-pack): drop CVE/secrets/audit tools from fetch script (Plan H.1)"
```

### Task 1.7: Update STATUS.md + README.md

**Files:**
- Modify: `docs/STATUS.md`
- Modify: `README.md`

- [ ] **Step 1: Update STATUS.md probe-count line**

Edit `docs/STATUS.md`. Find the line that reads `109 / 102 probes registered` and replace with:

```
98 / 98 probes registered (Plan H.1 trim — CVE/secrets/audit out of PQC scope; B17 OSV matcher and Plan F batch 4 Grype-DB bundle no longer applicable)
```

Update any per-family count tables that include the dropped probes.

- [ ] **Step 2: Update README.md status banner**

Replace the `> Status:` banner block with:

```markdown
> **Status: 98 probes shipped — see [docs/STATUS.md](docs/STATUS.md).** Plan H.1 trim complete: CVE family, secrets scanner, lynis, bandit dropped (all out of PQC scope). Plans A+B+C+D+E+F+G remain done; B17 OSV matcher and Plan F batch 4 Grype-DB bundle no longer applicable. UDP scan + DTLS foundation (Plan H.2) and OT/ICS family (Plan H.3) follow.
```

- [ ] **Step 3: Verify markdown renders**

```bash
grep -c "98 probes" README.md docs/STATUS.md
```

Expected: at least one match in each file.

- [ ] **Step 4: Commit**

```bash
git add docs/STATUS.md README.md
git commit -m "docs(status): Plan H.1 closeout — 98 probes (CVE/secrets/audit dropped)"
```

### Task 1.8: Final test sweep + tag v0.2.0

- [ ] **Step 1: Full test sweep**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
/tmp/pqcscan-venv311/bin/python -m ruff check src tests
/tmp/pqcscan-venv311/bin/python -m mypy src/pqcscan
```

Expected: pytest green, ruff clean, mypy clean. If any failure, fix in a follow-up commit before tagging.

- [ ] **Step 2: Smoke-run daemon**

```bash
/tmp/pqcscan-venv311/bin/python -m pqcscan daemon --db /tmp/pqcscan-h1-smoke.db &
sleep 3
curl -sS -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8765/
kill %1
```

Expected: HTTP 200.

- [ ] **Step 3: Tag**

```bash
git tag -a v0.2.0 -m "Plan H.1 — YAGNI trim (98 probes; CVE/secrets/audit dropped)"
```

---

## Phase 2 — H.2: UDP scan + DTLS foundation (target tag v0.3.0)

Add `_udp_payloads.py`, `_dtls_probe.py`, `net.ports.udp`. Registry 98 → 99.

### Task 2.1: Create _udp_payloads.py — protocol payload registry

**Files:**
- Create: `src/pqcscan/probes/_udp_payloads.py`

- [ ] **Step 1: Write the payload module**

`src/pqcscan/probes/_udp_payloads.py`:

```python
"""UDP probe payloads — one per well-known UDP service."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UDPPayload:
    port: int
    name: str
    payload: bytes
    expect_response: bool = True


def _ntp_client() -> bytes:
    return b"\x23" + b"\x00" * 47


def _snmp_v2c_get_sysdescr() -> bytes:
    return bytes.fromhex(
        "302902010104067075626c6963a01c0204"
        "1234567802010002010030103e0e060a2b"
        "06010201010100050000"
    )


def _ike_isakmp_init() -> bytes:
    initiator_spi = b"\x11" * 8
    responder_spi = b"\x00" * 8
    return initiator_spi + responder_spi + b"\x00\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x1c"


def _dns_root_query() -> bytes:
    return bytes.fromhex("1234010000010000000000000000010001")


def _bacnet_who_is() -> bytes:
    bvlc = b"\x81\x0b\x00\x0c"
    npdu = b"\x01\x20"
    apdu = b"\x10\x08"
    return bvlc + npdu + apdu


def _dnp3_link_status() -> bytes:
    return b"\x05\x64\x05\x09\x01\x00\x00\x00\x00\x00"


def _gtpv2c_echo() -> bytes:
    return bytes.fromhex("4801000400000001")


def _coap_get_well_known_core() -> bytes:
    header = b"\x40\x01\xbe\xef"
    opt1 = b"\xbb" + b".well-known"
    opt2 = b"\x04" + b"core"
    return header + opt1 + opt2


def _coaps_dtls_clienthello() -> bytes:
    return bytes.fromhex(
        "16fefd0000000000000000003a010000"
        "2e0000000000000000fefd0000000000"
        "00000000000000000000000000000000"
        "0000000000000000000000000000020014"
        "0100"
    )


DEFAULT_UDP_PORTS: tuple[UDPPayload, ...] = (
    UDPPayload(53,    "DNS",         _dns_root_query()),
    UDPPayload(123,   "NTP",         _ntp_client()),
    UDPPayload(161,   "SNMP",        _snmp_v2c_get_sysdescr()),
    UDPPayload(500,   "IKEv1/2",     _ike_isakmp_init()),
    UDPPayload(514,   "syslog",      b"", expect_response=False),
    UDPPayload(1812,  "RADIUS",      b"\x01\x01\x00\x14" + b"\x00" * 16),
    UDPPayload(1813,  "RADIUS-acct", b"", expect_response=False),
    UDPPayload(4500,  "IKE-NAT-T",   b"\x00\x00\x00\x00" + _ike_isakmp_init()),
    UDPPayload(4789,  "VXLAN",       b"", expect_response=False),
    UDPPayload(5060,  "SIP",         b"OPTIONS sip:probe@127.0.0.1 SIP/2.0\r\n\r\n"),
    UDPPayload(5353,  "mDNS",        _dns_root_query()),
    UDPPayload(5683,  "CoAP",        _coap_get_well_known_core()),
    UDPPayload(5684,  "CoAPS-DTLS",  _coaps_dtls_clienthello()),
    UDPPayload(6343,  "sFlow",       b"", expect_response=False),
    UDPPayload(20000, "DNP3",        _dnp3_link_status()),
    UDPPayload(2123,  "GTP-C",       _gtpv2c_echo()),
    UDPPayload(2152,  "GTP-U",       _gtpv2c_echo()),
    UDPPayload(47808, "BACnet",      _bacnet_who_is()),
)
```

- [ ] **Step 2: Quick sanity import**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._udp_payloads import DEFAULT_UDP_PORTS; print(len(DEFAULT_UDP_PORTS))"
```

Expected: `18`.

- [ ] **Step 3: Commit**

```bash
git add src/pqcscan/probes/_udp_payloads.py
git commit -m "feat(probes): UDP payload registry (Plan H.2)"
```

### Task 2.2: Create _dtls_probe.py — TDD

**Files:**
- Create: `src/pqcscan/probes/_dtls_probe.py`
- Test: `tests/probes/test_dtls_probe.py`

- [ ] **Step 1: Write failing test**

`tests/probes/test_dtls_probe.py`:

```python
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
```

- [ ] **Step 2: Run test, expect ImportError**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_dtls_probe.py -v
```

Expected: ImportError on `from pqcscan.probes._dtls_probe import run_dtls_probe`.

- [ ] **Step 3: Implement _dtls_probe.py**

`src/pqcscan/probes/_dtls_probe.py`:

```python
"""DTLS handshake probe — shells out to `openssl s_client -dtls<ver>`."""
from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass

from pqcscan.core.alg import classify
from pqcscan.core.types import Finding, Severity
from pqcscan.probes._base import Emitter


@dataclass(slots=True)
class DTLSHandshakeResult:
    version: str | None
    cipher: str | None
    peer_cert_subject: str | None
    raw: str
    algorithms: list[str]


_CIPHER_RE = re.compile(r"^\s*Cipher\s*:\s*(\S+)", re.MULTILINE)
_VERSION_RE = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.MULTILINE)
_SUBJECT_RE = re.compile(r"^\s*subject=([^\n]+)", re.MULTILINE)


def _parse_dtls_handshake(text: str) -> DTLSHandshakeResult:
    cipher_m = _CIPHER_RE.search(text)
    ver_m = _VERSION_RE.search(text)
    subj_m = _SUBJECT_RE.search(text)
    cipher = cipher_m.group(1) if cipher_m else None
    version = ver_m.group(1) if ver_m else None
    subject = subj_m.group(1).strip() if subj_m else None

    algos: list[str] = []
    if cipher:
        for token in cipher.split("-"):
            if token == "AES256":
                algos.append("AES-256")
            elif token == "AES128":
                algos.append("AES-128")
            elif token == "3DES":
                algos.append("3DES")
            elif token == "RC4":
                algos.append("RC4")
            elif token == "SHA384":
                algos.append("SHA-384")
            elif token == "SHA256":
                algos.append("SHA-256")
            elif token == "SHA1":
                algos.append("SHA-1")
            elif token == "MD5":
                algos.append("MD5")
            elif token in {"RSA", "ECDSA", "ECDHE", "DHE"}:
                algos.append(token)
    return DTLSHandshakeResult(
        version=version, cipher=cipher, peer_cert_subject=subject,
        raw=text, algorithms=algos,
    )


async def run_dtls_probe(
    *,
    host: str,
    port: int,
    version: str = "1.2",
    probe_id: str,
    emit: Emitter,
    timeout_s: float = 10.0,
) -> None:
    if shutil.which("openssl") is None:
        emit(Finding(
            probe_id=probe_id,
            asset=f"udp://{host}:{port}",
            severity=Severity.INFO,
            evidence={"skip_reason": "openssl binary not on PATH"},
        ))
        return

    flag = f"-dtls{version.replace('.', '_')}"
    args = [
        "openssl", "s_client", flag,
        "-connect", f"{host}:{port}",
    ]
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=b"\n"), timeout=timeout_s,
        )
    except (TimeoutError, asyncio.TimeoutError):
        proc.kill()
        emit(Finding(
            probe_id=probe_id,
            asset=f"udp://{host}:{port}",
            severity=Severity.INFO,
            evidence={"timeout_s": timeout_s, "version": version},
        ))
        return

    text = stdout_b.decode("utf-8", errors="replace") + "\n" + stderr_b.decode("utf-8", errors="replace")
    parsed = _parse_dtls_handshake(text)

    if not parsed.cipher and not parsed.algorithms:
        emit(Finding(
            probe_id=probe_id,
            asset=f"udp://{host}:{port}",
            severity=Severity.INFO,
            evidence={"reason": "no DTLS handshake parsed", "raw_head": text[:400]},
        ))
        return

    for alg in parsed.algorithms:
        emit(Finding(
            probe_id=probe_id,
            asset=f"udp://{host}:{port}",
            algorithm=alg,
            classification=classify(alg),
            severity=Severity.MEDIUM,
            evidence={
                "dtls_version": parsed.version,
                "cipher_suite": parsed.cipher,
                "peer_subject": parsed.peer_cert_subject,
            },
        ))
```

- [ ] **Step 4: Run test, expect PASS**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_dtls_probe.py -v
```

Expected: PASS (or SKIPPED if openssl missing).

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/_dtls_probe.py tests/probes/test_dtls_probe.py
git commit -m "feat(probes): _dtls_probe helper with openssl s_client shell-out (Plan H.2)"
```

### Task 2.3: Create net.ports.udp probe — TDD

**Files:**
- Create: `src/pqcscan/probes/net_ports_udp.py`
- Test: `tests/probes/test_net_ports_udp.py`

- [ ] **Step 1: Write failing test**

`tests/probes/test_net_ports_udp.py`:

```python
from __future__ import annotations

import asyncio
import socket
from typing import Any

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_ports_udp import NetPortsUDP


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def echo_udp_server():
    port = _free_udp_port()
    loop = asyncio.get_running_loop()

    class _EchoProto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport: Any) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Any) -> None:
            if self.transport:
                self.transport.sendto(b"PONG:" + data[:32], addr)

    transport, _ = await loop.create_datagram_endpoint(
        _EchoProto, local_addr=("127.0.0.1", port),
    )
    try:
        yield "127.0.0.1", port
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_targeted_mode_open_port_emits_finding(echo_udp_server):
    host, port = echo_udp_server
    probe = NetPortsUDP(host=host, ports=[port], mode="targeted", timeout_s=1.0)
    findings: list[Finding] = []

    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, findings.append)

    assert len(findings) == 1
    assert findings[0].evidence["state"] == "open"
    assert findings[0].evidence["port"] == port


@pytest.mark.asyncio
async def test_targeted_mode_closed_port_emits_filtered():
    closed_port = _free_udp_port()
    probe = NetPortsUDP(host="127.0.0.1", ports=[closed_port], mode="targeted", timeout_s=0.5)
    findings: list[Finding] = []
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, findings.append)

    assert len(findings) == 1
    assert findings[0].evidence["state"] in {"closed", "filtered", "open|filtered"}
```

- [ ] **Step 2: Run, expect ImportError**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_net_ports_udp.py -v
```

- [ ] **Step 3: Implement net_ports_udp.py**

`src/pqcscan/probes/net_ports_udp.py`:

```python
"""UDP port scan probe."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._udp_payloads import DEFAULT_UDP_PORTS, UDPPayload


class NetPortsUDP(Probe):
    id = "net.ports.udp"
    family = ProbeFamily.NETWORK
    framework_tags = ("nacsa-9:port-discovery", "bukukerja:port-discovery")
    requires = frozenset()

    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: list[int] | None = None,
        timeout_s: float = 2.0,
        mode: str = "auto",
    ) -> None:
        self.host = host
        self.ports = ports
        self.timeout_s = timeout_s
        self.mode = mode

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    def _resolve_mode(self, ctx: ScanContext) -> str:
        if self.mode in ("raw", "targeted"):
            return self.mode
        if Capability.NET_RAW in ctx.available_capabilities:
            return "raw"
        return "targeted"

    def _payload_for(self, port: int) -> UDPPayload:
        for p in DEFAULT_UDP_PORTS:
            if p.port == port:
                return p
        return UDPPayload(port=port, name=f"unknown-{port}", payload=b"", expect_response=False)

    async def _probe_targeted(self, port: int) -> tuple[str, dict[str, Any]]:
        payload = self._payload_for(port)
        loop = asyncio.get_running_loop()
        future_resp: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: Any) -> None:
                if not future_resp.done():
                    future_resp.set_result(data)

            def error_received(self, exc: Exception) -> None:
                if not future_resp.done():
                    future_resp.set_exception(exc)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(self.host, port),
            )
        except OSError as e:
            return "filtered", {"port": port, "error": repr(e), "name": payload.name}

        try:
            transport.sendto(payload.payload)
            if not payload.expect_response:
                return "open|filtered", {"port": port, "name": payload.name, "no_response_expected": True}
            try:
                resp = await asyncio.wait_for(future_resp, timeout=self.timeout_s)
                return "open", {
                    "port": port, "name": payload.name,
                    "response_len": len(resp),
                    "response_head_hex": resp[:32].hex(),
                }
            except (TimeoutError, asyncio.TimeoutError):
                return "open|filtered", {"port": port, "name": payload.name, "timeout_s": self.timeout_s}
            except OSError as e:
                return "closed", {"port": port, "name": payload.name, "error": repr(e)}
        finally:
            transport.close()

    async def _probe_raw(self, port: int) -> tuple[str, dict[str, Any]]:
        # Raw-mode ICMP capture deferred — fall through to targeted.
        return await self._probe_targeted(port)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        mode = self._resolve_mode(ctx)
        ports = self.ports or [p.port for p in DEFAULT_UDP_PORTS]

        async def _one(port: int) -> None:
            if mode == "raw":
                state, evidence = await self._probe_raw(port)
            else:
                state, evidence = await self._probe_targeted(port)
            evidence = {"state": state, "mode": mode, **evidence}
            sev = Severity.INFO if state in ("closed", "filtered") else Severity.LOW
            emit(Finding(
                probe_id=self.id,
                asset=f"udp://{self.host}:{port}",
                classification=Classification.INFO,
                severity=sev,
                evidence=evidence,
            ))

        await asyncio.gather(*(_one(p) for p in ports))
```

- [ ] **Step 4: Run tests, expect PASS**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_net_ports_udp.py -v
```

Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/net_ports_udp.py tests/probes/test_net_ports_udp.py
git commit -m "feat(probes): net.ports.udp targeted-mode UDP scan (Plan H.2)"
```

### Task 2.4: Register net.ports.udp in default_registry()

**Files:**
- Modify: `src/pqcscan/probes/_registry.py`

- [ ] **Step 1: Add import + registration**

In `src/pqcscan/probes/_registry.py`, add at top:

```python
from pqcscan.probes.net_ports_udp import NetPortsUDP
```

Inside `default_registry()`:

```python
reg.add(NetPortsUDP())
```

- [ ] **Step 2: Verify count**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"
```

Expected: `99`.

- [ ] **Step 3: Commit**

```bash
git add src/pqcscan/probes/_registry.py
git commit -m "feat(registry): register net.ports.udp (Plan H.2)"
```

### Task 2.5: Status doc + tag v0.3.0

**Files:**
- Modify: `docs/STATUS.md`
- Modify: `README.md`

- [ ] **Step 1: Bump status counts**

Replace `98 / 98 probes` with `99 / 99 probes (UDP scan + DTLS foundation added)` in `docs/STATUS.md` and `README.md`.

- [ ] **Step 2: Add Plan H.2 row to "what's shipped" table**

```
| **Plan H.1** | YAGNI trim — CVE/secrets/audit dropped (98 probes) |
| **Plan H.2** | UDP port scan (`net.ports.udp`) + `_dtls_probe` helper + 18-port targeted payload registry |
```

- [ ] **Step 3: Test sweep**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
```

Expected: green.

- [ ] **Step 4: Commit + tag**

```bash
git add docs/STATUS.md README.md
git commit -m "docs(status): Plan H.2 closeout — 99 probes (UDP+DTLS)"
git tag -a v0.3.0 -m "Plan H.2 — UDP scan + DTLS foundation"
```

---

## Phase 3a — H.3a: OT TCP binary parsers (target tag v0.4.0)

Add `ProbeFamily.OT`, `ScanContext.ot_targets`, `_binary_proto.py`, 7 OT TCP probes. Registry 99 → 106.

### Task 3.0: Add ProbeFamily.OT enum value

**Files:**
- Modify: `src/pqcscan/core/types.py`

- [ ] **Step 1: Read current ProbeFamily enum**

```bash
grep -n "class ProbeFamily" -A 25 src/pqcscan/core/types.py
```

- [ ] **Step 2: Add OT entry**

Add `OT = "ot"` to the `ProbeFamily(str, Enum)` body.

- [ ] **Step 3: Quick sanity**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.core.types import ProbeFamily; print(ProbeFamily.OT.value)"
```

Expected: `ot`.

- [ ] **Step 4: Commit**

```bash
git add src/pqcscan/core/types.py
git commit -m "feat(core): add ProbeFamily.OT (Plan H.3)"
```

### Task 3.0.1: Extend ScanContext with ot_targets

**Files:**
- Modify: `src/pqcscan/probes/_base.py`

- [ ] **Step 1: Read current ScanContext**

```bash
grep -n "class ScanContext\|@dataclass" -A 12 src/pqcscan/probes/_base.py
```

- [ ] **Step 2: Add OTTarget dataclass + extend ScanContext**

Add above `ScanContext`:

```python
@dataclass(slots=True)
class OTTarget:
    host: str
    port: int
    proto_hint: str | None = None
```

Add to `ScanContext`:

```python
ot_targets: list["OTTarget"] = field(default_factory=list)
```

- [ ] **Step 3: Sanity import**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._base import ScanContext, OTTarget; ctx=ScanContext(scan_id=1, mode='user', available_capabilities=set()); print(ctx.ot_targets)"
```

Expected: `[]`.

- [ ] **Step 4: Commit**

```bash
git add src/pqcscan/probes/_base.py
git commit -m "feat(probes): ScanContext.ot_targets + OTTarget dataclass (Plan H.3)"
```

### Task 3.0.2: Create _binary_proto.py — TDD

**Files:**
- Create: `src/pqcscan/probes/_binary_proto.py`
- Test: `tests/probes/test_binary_proto.py`

- [ ] **Step 1: Write failing test**

`tests/probes/test_binary_proto.py`:

```python
from __future__ import annotations

import asyncio

import pytest

from pqcscan.probes._binary_proto import read_frame


class _MockReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    async def readexactly(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise asyncio.IncompleteReadError(self.data[self.offset:], n)
        chunk = self.data[self.offset : self.offset + n]
        self.offset += n
        return chunk


@pytest.mark.asyncio
async def test_read_frame_simple_length_prefix():
    data = b"\x00\x05" + b"\x00\x00" + b"hello"
    reader = _MockReader(data)
    frame = await read_frame(reader, header_len=4, len_offset=0, len_size=2)
    assert frame == b"\x00\x05\x00\x00hello"


@pytest.mark.asyncio
async def test_read_frame_rejects_oversized():
    data = b"\xff\xff" + b"\x00\x00"
    reader = _MockReader(data)
    with pytest.raises(ValueError, match="frame too large"):
        await read_frame(reader, header_len=4, len_offset=0, len_size=2, max_size=100)
```

- [ ] **Step 2: Run, expect ImportError**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_binary_proto.py -v
```

- [ ] **Step 3: Implement _binary_proto.py**

`src/pqcscan/probes/_binary_proto.py`:

```python
"""Length-prefix TCP frame helper, shared by OT binary-protocol probes."""
from __future__ import annotations

from typing import Protocol


class _Reader(Protocol):
    async def readexactly(self, n: int) -> bytes: ...


async def read_frame(
    reader: _Reader,
    *,
    header_len: int,
    len_offset: int,
    len_size: int,
    max_size: int = 65535,
    body_includes_header: bool = False,
) -> bytes:
    header = await reader.readexactly(header_len)
    if len_size == 1:
        body_len = header[len_offset]
    elif len_size == 2:
        body_len = int.from_bytes(header[len_offset : len_offset + 2], "big")
    elif len_size == 4:
        body_len = int.from_bytes(header[len_offset : len_offset + 4], "big")
    else:
        raise ValueError(f"unsupported len_size: {len_size}")

    if body_includes_header:
        body_len = max(0, body_len - header_len)

    if body_len > max_size:
        raise ValueError(f"frame too large: {body_len} > {max_size}")

    body = await reader.readexactly(body_len) if body_len > 0 else b""
    return header + body
```

- [ ] **Step 4: Run, expect PASS**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_binary_proto.py -v
```

Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/_binary_proto.py tests/probes/test_binary_proto.py
git commit -m "feat(probes): _binary_proto length-prefix frame helper (Plan H.3)"
```

### Task 3.1: ot.modbus.tcp probe — TDD

**Files:**
- Create: `src/pqcscan/probes/ot_modbus_tcp.py`
- Test: `tests/probes/test_ot_modbus_tcp.py`

- [ ] **Step 1: Write failing test**

`tests/probes/test_ot_modbus_tcp.py`:

```python
from __future__ import annotations

import asyncio
import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_modbus_tcp import OTModbusTcp


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def modbus_server():
    port = _free_port()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readexactly(8)
        except asyncio.IncompleteReadError:
            writer.close()
            return
        resp = bytes.fromhex("00010000000901") + bytes.fromhex("2b0e0101000001000441434d45")
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", port)
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_ot_modbus_tcp_emits_no_crypto_finding(modbus_server):
    host, port = modbus_server
    probe = OTModbusTcp()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="modbus")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    f = findings[0]
    assert f.probe_id == "ot.modbus.tcp"
    assert f.evidence.get("plain_modbus") is True
    assert f.evidence.get("vendor_name") == "ACME"
```

- [ ] **Step 2: Run, expect ImportError**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_modbus_tcp.py -v
```

- [ ] **Step 3: Implement ot_modbus_tcp.py**

`src/pqcscan/probes/ot_modbus_tcp.py`:

```python
"""ot.modbus.tcp — detects plain (unencrypted) Modbus/TCP devices."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _read_device_id_request(unit_id: int = 1, txn_id: int = 1) -> bytes:
    pdu = b"\x2b\x0e\x01\x00"
    mbap = (
        txn_id.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + bytes([unit_id])
    )
    return mbap + pdu


def _parse_read_device_id(resp: bytes) -> dict[str, Any]:
    if len(resp) < 7 + 8:
        return {}
    pdu = resp[7:]
    if pdu[:2] != b"\x2b\x0e":
        return {}
    n = pdu[6] if len(pdu) > 6 else 0
    out: dict[str, Any] = {"object_count": n}
    cursor = 7
    if n >= 1 and len(pdu) >= cursor + 2:
        obj_id = pdu[cursor]
        obj_len = pdu[cursor + 1]
        if len(pdu) >= cursor + 2 + obj_len:
            value = pdu[cursor + 2 : cursor + 2 + obj_len].decode("utf-8", errors="replace")
            if obj_id == 0:
                out["vendor_name"] = value
    return out


class OTModbusTcp(Probe):
    id = "ot.modbus.tcp"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "modbus") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "modbus")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=502, proto_hint="modbus")]
        for target in targets:
            await self._probe_one(target, emit)

    async def _probe_one(self, target: OTTarget, emit: Emitter) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout=3.0,
            )
        except (OSError, TimeoutError, asyncio.TimeoutError) as e:
            emit(Finding(
                probe_id=self.id,
                asset=f"tcp://{target.host}:{target.port}",
                severity=Severity.INFO,
                evidence={"reachable": False, "error": repr(e)},
            ))
            return

        try:
            writer.write(_read_device_id_request())
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
            except (TimeoutError, asyncio.TimeoutError):
                resp = b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        parsed = _parse_read_device_id(resp)
        emit(Finding(
            probe_id=self.id,
            asset=f"tcp://{target.host}:{target.port}",
            classification=Classification.INFO,
            severity=Severity.HIGH,
            evidence={
                "plain_modbus": True,
                "transport": "TCP",
                "no_crypto": True,
                "response_len": len(resp),
                **parsed,
            },
        ))
```

- [ ] **Step 4: Run, expect PASS**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_modbus_tcp.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/ot_modbus_tcp.py tests/probes/test_ot_modbus_tcp.py
git commit -m "feat(probes): ot.modbus.tcp — plain Modbus/TCP detection (Plan H.3a)"
```

### Task 3.2: ot.modbus_secure.tls probe

**Files:**
- Create: `src/pqcscan/probes/ot_modbus_secure.py`
- Test: `tests/probes/test_ot_modbus_secure.py`

- [ ] **Step 1: Write minimal test**

`tests/probes/test_ot_modbus_secure.py`:

```python
from __future__ import annotations

import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_modbus_secure import OTModbusSecure


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_ot_modbus_secure_unreachable_emits_info():
    port = _free_port()
    probe = OTModbusSecure()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host="127.0.0.1", port=port, proto_hint="modbus_secure")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) == 1
    assert findings[0].evidence.get("reachable") is False
```

- [ ] **Step 2: Run, expect ImportError**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_modbus_secure.py -v
```

- [ ] **Step 3: Implement ot_modbus_secure.py**

`src/pqcscan/probes/ot_modbus_secure.py`:

```python
"""ot.modbus_secure.tls — wraps _tls_probe against Modbus-Secure (TCP/802)."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTModbusSecure(Probe):
    id = "ot.modbus_secure.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "modbus_secure") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "modbus_secure")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=802, proto_hint="modbus_secure")]
        for target in targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=2.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
```

- [ ] **Step 4: Run, expect PASS**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_modbus_secure.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/ot_modbus_secure.py tests/probes/test_ot_modbus_secure.py
git commit -m "feat(probes): ot.modbus_secure.tls — TLS-wrapped Modbus on 802 (Plan H.3a)"
```

### Task 3.3: ot.s7comm probe

**Files:**
- Create: `src/pqcscan/probes/ot_s7comm.py`
- Test: `tests/probes/test_ot_s7comm.py`

- [ ] **Step 1: Write fixture-based test**

`tests/probes/test_ot_s7comm.py`:

```python
from __future__ import annotations

import asyncio
import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_s7comm import OTS7comm


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def s7_server():
    port = _free_port()

    async def handler(reader, writer):
        try:
            await reader.read(1024)
        except Exception:
            pass
        resp = bytes.fromhex("0300001611d000010002000c0a0001000200a0c20100c2020102")
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", port)
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_ot_s7comm_emits_no_crypto(s7_server):
    host, port = s7_server
    probe = OTS7comm()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="s7")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("plain_s7") is True
```

- [ ] **Step 2: Run, expect ImportError**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_s7comm.py -v
```

- [ ] **Step 3: Implement ot_s7comm.py**

`src/pqcscan/probes/ot_s7comm.py`:

```python
"""ot.s7comm — detects plain Siemens S7 protocol over TPKT/COTP/TCP."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _cotp_cr_request() -> bytes:
    cotp = bytes.fromhex("11e0000000010000c1020100c2020102c0010a")
    tpkt = b"\x03\x00" + (4 + len(cotp)).to_bytes(2, "big")
    return tpkt + cotp


class OTS7comm(Probe):
    id = "ot.s7comm"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "s7") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "s7")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=102, proto_hint="s7")]

        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_cotp_cr_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            cotp_cc_ok = len(resp) >= 6 and resp[0] == 0x03 and resp[5] == 0xD0
            emit(Finding(
                probe_id=self.id,
                asset=f"tcp://{target.host}:{target.port}",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                evidence={
                    "plain_s7": cotp_cc_ok,
                    "transport": "TPKT/COTP/TCP",
                    "no_crypto": True,
                    "cotp_cc_observed": cotp_cc_ok,
                    "response_len": len(resp),
                },
            ))
```

- [ ] **Step 4: Run, expect PASS**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_s7comm.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/pqcscan/probes/ot_s7comm.py tests/probes/test_ot_s7comm.py
git commit -m "feat(probes): ot.s7comm — plain Siemens S7 detection (Plan H.3a)"
```

### Task 3.4: ot.dnp3.tcp probe

**Files:**
- Create: `src/pqcscan/probes/ot_dnp3_tcp.py`
- Test: `tests/probes/test_ot_dnp3_tcp.py`

- [ ] **Step 1: Test using fixture server**

`tests/probes/test_ot_dnp3_tcp.py`:

```python
from __future__ import annotations

import asyncio
import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_dnp3_tcp import OTDnp3Tcp


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def dnp3_server():
    port = _free_port()

    async def handler(reader, writer):
        try:
            await reader.read(1024)
        except Exception:
            pass
        resp = bytes.fromhex("0564050b01000000affe")
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", port)
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_ot_dnp3_emits_no_sa(dnp3_server):
    host, port = dnp3_server
    probe = OTDnp3Tcp()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="dnp3")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("secure_auth_present") is False
```

- [ ] **Step 2: Run, implement, run again**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_dnp3_tcp.py -v
```

- [ ] **Step 3: Implement ot_dnp3_tcp.py**

`src/pqcscan/probes/ot_dnp3_tcp.py`:

```python
"""ot.dnp3.tcp — detects DNP3 outstations and DNP3 Secure Authentication state."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _dnp3_link_status_request() -> bytes:
    return bytes.fromhex("0564050901000000ffff")


class OTDnp3Tcp(Probe):
    id = "ot.dnp3.tcp"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "dnp3") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "dnp3")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=20000, proto_hint="dnp3")]

        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_dnp3_link_status_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            dnp3_observed = len(resp) >= 4 and resp[:2] == b"\x05\x64"
            secure_auth_present = b"\x78" in resp[8:32]
            emit(Finding(
                probe_id=self.id,
                asset=f"tcp://{target.host}:{target.port}",
                classification=Classification.INFO,
                severity=Severity.HIGH if not secure_auth_present else Severity.MEDIUM,
                evidence={
                    "transport": "TCP",
                    "dnp3_observed": dnp3_observed,
                    "secure_auth_present": secure_auth_present,
                    "no_crypto": not secure_auth_present,
                    "response_len": len(resp),
                },
            ))
```

- [ ] **Step 4: Run + commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_dnp3_tcp.py -v
git add src/pqcscan/probes/ot_dnp3_tcp.py tests/probes/test_ot_dnp3_tcp.py
git commit -m "feat(probes): ot.dnp3.tcp — DNP3 outstation + SA detection (Plan H.3a)"
```

### Task 3.5: ot.iec_104.startdt probe

**Files:**
- Create: `src/pqcscan/probes/ot_iec_104.py`
- Test: `tests/probes/test_ot_iec_104.py`

- [ ] **Step 1: Test**

`tests/probes/test_ot_iec_104.py`:

```python
from __future__ import annotations

import asyncio
import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_iec_104 import OTIec104


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def iec104_server():
    port = _free_port()

    async def handler(reader, writer):
        try:
            await reader.read(64)
        except Exception:
            pass
        resp = bytes.fromhex("680483000000")
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", port)
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_ot_iec_104_no_crypto(iec104_server):
    host, port = iec104_server
    probe = OTIec104()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="iec104")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("startdt_con") is True
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_iec_104.py`:

```python
"""ot.iec_104.startdt — IEC 60870-5-104 STARTDT handshake; flags absence of TLS."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _startdt_act() -> bytes:
    return bytes.fromhex("680407000000")


class OTIec104(Probe):
    id = "ot.iec_104.startdt"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "iec104") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "iec104")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=2404, proto_hint="iec104")]

        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_startdt_act())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(64), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            startdt_con = len(resp) >= 6 and resp[0] == 0x68 and resp[2] == 0x83
            emit(Finding(
                probe_id=self.id,
                asset=f"tcp://{target.host}:{target.port}",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                evidence={
                    "transport": "TCP",
                    "startdt_con": startdt_con,
                    "no_crypto": True,
                    "iec_62351_3_tls_wrap_detected": False,
                    "response_len": len(resp),
                },
            ))
```

- [ ] **Step 3: Run + commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_iec_104.py -v
git add src/pqcscan/probes/ot_iec_104.py tests/probes/test_ot_iec_104.py
git commit -m "feat(probes): ot.iec_104.startdt — IEC 60870-5-104 plain detection (Plan H.3a)"
```

### Task 3.6: ot.iec_61850.mms probe

**Files:**
- Create: `src/pqcscan/probes/ot_iec_61850_mms.py`
- Test: `tests/probes/test_ot_iec_61850_mms.py`

- [ ] **Step 1: Test**

`tests/probes/test_ot_iec_61850_mms.py`:

```python
from __future__ import annotations

import asyncio
import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_iec_61850_mms import OTIec61850Mms


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def mms_server():
    port = _free_port()

    async def handler(reader, writer):
        try:
            await reader.read(2048)
        except Exception:
            pass
        resp = bytes.fromhex("0300001702f080a883060001000000a205800200008101")
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", port)
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_ot_iec_61850_mms_plain(mms_server):
    host, port = mms_server
    probe = OTIec61850Mms()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="iec61850")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("plain_mms") is True
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_iec_61850_mms.py`:

```python
"""ot.iec_61850.mms — IEC 61850 MMS Initiate over plain TCP/102."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _mms_initiate_request() -> bytes:
    return bytes.fromhex("030000160ee00000000100c1020100c2020102")


class OTIec61850Mms(Probe):
    id = "ot.iec_61850.mms"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "iec61850") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "iec61850")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=102, proto_hint="iec61850")]

        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_mms_initiate_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            tpkt_ok = len(resp) >= 4 and resp[0] == 0x03 and resp[1] == 0x00
            emit(Finding(
                probe_id=self.id,
                asset=f"tcp://{target.host}:{target.port}",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                evidence={
                    "transport": "ISO/TCP-102",
                    "plain_mms": tpkt_ok,
                    "no_crypto": True,
                    "iec_62351_4_tls_detected": False,
                    "response_len": len(resp),
                },
            ))
```

- [ ] **Step 3: Run + commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_iec_61850_mms.py -v
git add src/pqcscan/probes/ot_iec_61850_mms.py tests/probes/test_ot_iec_61850_mms.py
git commit -m "feat(probes): ot.iec_61850.mms — plain MMS detection (Plan H.3a)"
```

### Task 3.7: ot.ethernet_ip.list_id probe

**Files:**
- Create: `src/pqcscan/probes/ot_ethernet_ip.py`
- Test: `tests/probes/test_ot_ethernet_ip.py`

- [ ] **Step 1: Test**

`tests/probes/test_ot_ethernet_ip.py`:

```python
from __future__ import annotations

import asyncio
import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_ethernet_ip import OTEthernetIp


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def enip_server():
    port = _free_port()

    async def handler(reader, writer):
        try:
            await reader.read(64)
        except Exception:
            pass
        resp = bytes.fromhex("63003a0000000000000000000000000000000000010030010000020001")
        resp += b"\x00" * (62 - len(resp))
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", port)
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_ot_ethernet_ip_no_cipsec(enip_server):
    host, port = enip_server
    probe = OTEthernetIp()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="enip")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("plain_enip") is True
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_ethernet_ip.py`:

```python
"""ot.ethernet_ip.list_id — EtherNet/IP ListIdentity over plain TCP/44818."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _list_identity_request() -> bytes:
    return bytes(24).replace(b"\x00\x00", b"\x63\x00", 1)


class OTEthernetIp(Probe):
    id = "ot.ethernet_ip.list_id"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "enip") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "enip")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=44818, proto_hint="enip")]

        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_list_identity_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(512), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            enip_ok = len(resp) >= 4 and resp[:2] == b"\x63\x00"
            emit(Finding(
                probe_id=self.id,
                asset=f"tcp://{target.host}:{target.port}",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                evidence={
                    "transport": "TCP/44818",
                    "plain_enip": enip_ok,
                    "no_crypto": True,
                    "cip_security_detected": False,
                    "response_len": len(resp),
                },
            ))
```

- [ ] **Step 3: Run + commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_ethernet_ip.py -v
git add src/pqcscan/probes/ot_ethernet_ip.py tests/probes/test_ot_ethernet_ip.py
git commit -m "feat(probes): ot.ethernet_ip.list_id — plain EtherNet/IP detection (Plan H.3a)"
```

### Task 3.8: Register all 7 H.3a probes + NACSA YAML extend

**Files:**
- Modify: `src/pqcscan/probes/_registry.py`
- Modify: `src/pqcscan/compliance/frameworks/nacsa-arahan-ke-9.yaml`
- Modify: `src/pqcscan/compliance/frameworks/bukukerja.yaml`

- [ ] **Step 1: Add registry imports + adds**

In `src/pqcscan/probes/_registry.py`:

```python
from pqcscan.probes.ot_modbus_tcp import OTModbusTcp
from pqcscan.probes.ot_modbus_secure import OTModbusSecure
from pqcscan.probes.ot_s7comm import OTS7comm
from pqcscan.probes.ot_dnp3_tcp import OTDnp3Tcp
from pqcscan.probes.ot_iec_104 import OTIec104
from pqcscan.probes.ot_iec_61850_mms import OTIec61850Mms
from pqcscan.probes.ot_ethernet_ip import OTEthernetIp
```

Inside `default_registry()`:

```python
reg.add(OTModbusTcp())
reg.add(OTModbusSecure())
reg.add(OTS7comm())
reg.add(OTDnp3Tcp())
reg.add(OTIec104())
reg.add(OTIec61850Mms())
reg.add(OTEthernetIp())
```

- [ ] **Step 2: Verify count = 106**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"
```

- [ ] **Step 3: Extend NACSA YAML**

Append to `src/pqcscan/compliance/frameworks/nacsa-arahan-ke-9.yaml`:

```yaml
  # ───── OT/ICS clauses (Plan H.3) ─────
  - match: { probe_family: ot, classification: info }
    clause: NACSA-9:ot-no-crypto
    verdict: non-compliant
    deadline: 2027-06-30
    note: "Protokol OT tanpa kriptografi (Modbus/S7/DNP3/IEC-104/EtherNet-IP/BACnet plain). Wajib dilindungi (TLS-wrap atau IEC 62351 / CIP Security / BACnet-SC) menjelang Fasa 4 (Jun 2027)."
```

- [ ] **Step 4: Extend BUKUKERJA YAML**

Append to `src/pqcscan/compliance/frameworks/bukukerja.yaml`:

```yaml
  - match: { probe_family: ot }
    clause: BUKUKERJA:ot-protocol
    note: "Protokol OT direkodkan dalam Jadual 2 (CBOM) dan Jadual 3 (RiskRegister)."
```

- [ ] **Step 5: Run full suite**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add src/pqcscan/probes/_registry.py \
        src/pqcscan/compliance/frameworks/nacsa-arahan-ke-9.yaml \
        src/pqcscan/compliance/frameworks/bukukerja.yaml
git commit -m "feat(registry,compliance): register 7 OT TCP probes + NACSA/BUKUKERJA OT clauses (Plan H.3a)"
```

### Task 3.9: Status doc + tag v0.4.0

- [ ] **Step 1: STATUS + README bump**

Update `docs/STATUS.md` and `README.md`: probe count `99` → `106`. Add row "Plan H.3a — OT TCP binary parsers (Modbus / Modbus-Secure / S7 / DNP3 / IEC-104 / IEC-61850-MMS / EtherNet-IP)".

- [ ] **Step 2: Test sweep**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
/tmp/pqcscan-venv311/bin/python -m ruff check src tests
/tmp/pqcscan-venv311/bin/python -m mypy src/pqcscan
```

- [ ] **Step 3: Tag**

```bash
git add docs/STATUS.md README.md
git commit -m "docs(status): Plan H.3a closeout — 106 probes (OT TCP family)"
git tag -a v0.4.0 -m "Plan H.3a — OT/ICS TCP binary parsers (7 probes)"
```

---

## Phase 3b — H.3b: TLS-wrapped + OPC UA + BACnet (target tag v0.4.1)

### Task 4.1: ot.opc_ua.endpoint_security probe

**Files:**
- Create: `src/pqcscan/probes/ot_opc_ua.py`
- Test: `tests/probes/test_ot_opc_ua.py`

- [ ] **Step 1: Write parser-focused test**

`tests/probes/test_ot_opc_ua.py`:

```python
from __future__ import annotations

import pytest

from pqcscan.probes.ot_opc_ua import _parse_security_policies


def test_parse_security_policies_basic128rsa15():
    response = (
        b"http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15\x00"
        b"http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    )
    policies = _parse_security_policies(response)
    assert "Basic128Rsa15" in policies
    assert "Aes256_Sha256_RsaPss" in policies


def test_parse_security_policies_none_only():
    response = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    policies = _parse_security_policies(response)
    assert policies == ["None"]
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_opc_ua.py`:

```python
"""ot.opc_ua.endpoint_security — OPC UA GetEndpoints + SecurityPolicy classification."""
from __future__ import annotations

import asyncio
import re

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


_POLICY_RE = re.compile(rb"SecurityPolicy#([A-Za-z0-9_]+)")


def _parse_security_policies(blob: bytes) -> list[str]:
    return [m.decode("ascii") for m in _POLICY_RE.findall(blob)]


_HELLO_FRAME = bytes.fromhex(
    "48454c4658000000ffffff7f00000100"
    "0000000020000000"
)


class OTOpcUa(Probe):
    id = "ot.opc_ua.endpoint_security"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "opcua") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "opcua")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=4840, proto_hint="opcua")]

        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_HELLO_FRAME)
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(8192), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            policies = _parse_security_policies(resp)
            if not policies:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reason": "no SecurityPolicy URIs parsed", "response_len": len(resp)},
                ))
                continue
            for pol in policies:
                if pol in ("Basic128Rsa15", "Basic256"):
                    sev = Severity.HIGH
                    cls = Classification.INFO
                elif pol == "None":
                    sev = Severity.HIGH
                    cls = Classification.INFO
                else:
                    sev = Severity.MEDIUM
                    cls = classify(pol) if classify else Classification.INFO

                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    algorithm=pol,
                    classification=cls,
                    severity=sev,
                    evidence={
                        "security_policy_uri": f"http://opcfoundation.org/UA/SecurityPolicy#{pol}",
                        "transport": "OPC-UA-binary",
                    },
                ))
```

- [ ] **Step 3: Run + commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_opc_ua.py -v
git add src/pqcscan/probes/ot_opc_ua.py tests/probes/test_ot_opc_ua.py
git commit -m "feat(probes): ot.opc_ua.endpoint_security — SecurityPolicy classification (Plan H.3b)"
```

### Task 4.2: ot.cip_security.tls probe

**Files:**
- Create: `src/pqcscan/probes/ot_cip_security.py`
- Test: `tests/probes/test_ot_cip_security.py`

- [ ] **Step 1: Test (unreachable path)**

`tests/probes/test_ot_cip_security.py`:

```python
from __future__ import annotations

import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_cip_security import OTCipSecurity


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_ot_cip_security_unreachable():
    port = _free_port()
    probe = OTCipSecurity()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host="127.0.0.1", port=port, proto_hint="cip_security")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) == 1
    assert findings[0].evidence.get("reachable") is False
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_cip_security.py`:

```python
"""ot.cip_security.tls — TLS handshake on EtherNet/IP CIP-Security port (2222)."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTCipSecurity(Probe):
    id = "ot.cip_security.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "cip_security") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "cip_security")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=2222, proto_hint="cip_security")]
        for target in targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=2.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_cip_security.py -v
git add src/pqcscan/probes/ot_cip_security.py tests/probes/test_ot_cip_security.py
git commit -m "feat(probes): ot.cip_security.tls — EtherNet/IP CIP Security TLS (Plan H.3b)"
```

### Task 4.3: ot.bacnet.bvlc probe (UDP/47808)

**Files:**
- Create: `src/pqcscan/probes/ot_bacnet.py`
- Test: `tests/probes/test_ot_bacnet.py`

- [ ] **Step 1: Test using mini UDP server**

`tests/probes/test_ot_bacnet.py`:

```python
from __future__ import annotations

import asyncio
import socket
from typing import Any

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_bacnet import OTBacnet


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def bacnet_server():
    port = _free_udp_port()
    loop = asyncio.get_running_loop()

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport: Any) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Any) -> None:
            resp = bytes.fromhex("810a000c01001000c4020000010401")
            if self.transport:
                self.transport.sendto(resp, addr)

    transport, _ = await loop.create_datagram_endpoint(_Proto, local_addr=("127.0.0.1", port))
    try:
        yield "127.0.0.1", port
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_ot_bacnet_plain_no_crypto(bacnet_server):
    host, port = bacnet_server
    probe = OTBacnet()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="bacnet")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("plain_bacnet") is True
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_bacnet.py`:

```python
"""ot.bacnet.bvlc — BACnet/IP Who-Is over UDP/47808; flags absence of BACnet/SC."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _who_is() -> bytes:
    bvlc = b"\x81\x0b\x00\x0c"
    npdu = b"\x01\x20"
    apdu = b"\x10\x08"
    return bvlc + npdu + apdu


class OTBacnet(Probe):
    id = "ot.bacnet.bvlc"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "bacnet") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "bacnet")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=47808, proto_hint="bacnet")]

        for target in targets:
            await self._probe_one(target, emit)

    async def _probe_one(self, target: OTTarget, emit: Emitter) -> None:
        loop = asyncio.get_running_loop()
        future_resp: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: Any) -> None:
                if not future_resp.done():
                    future_resp.set_result(data)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(target.host, target.port),
            )
        except OSError as e:
            emit(Finding(
                probe_id=self.id,
                asset=f"udp://{target.host}:{target.port}",
                severity=Severity.INFO,
                evidence={"reachable": False, "error": repr(e)},
            ))
            return
        try:
            transport.sendto(_who_is())
            try:
                resp = await asyncio.wait_for(future_resp, timeout=2.0)
            except (TimeoutError, asyncio.TimeoutError):
                resp = b""
        finally:
            transport.close()

        bvlc_ok = len(resp) >= 4 and resp[0] == 0x81
        emit(Finding(
            probe_id=self.id,
            asset=f"udp://{target.host}:{target.port}",
            classification=Classification.INFO,
            severity=Severity.HIGH,
            evidence={
                "transport": "UDP/47808",
                "plain_bacnet": bvlc_ok,
                "no_crypto": True,
                "bacnet_sc_detected": False,
                "response_len": len(resp),
            },
        ))
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_bacnet.py -v
git add src/pqcscan/probes/ot_bacnet.py tests/probes/test_ot_bacnet.py
git commit -m "feat(probes): ot.bacnet.bvlc — plain BACnet/IP detection (Plan H.3b)"
```

### Task 4.4: ot.bacnet_sc.tls probe

**Files:**
- Create: `src/pqcscan/probes/ot_bacnet_sc.py`
- Test: `tests/probes/test_ot_bacnet_sc.py`

- [ ] **Step 1: Test (unreachable path)**

`tests/probes/test_ot_bacnet_sc.py`:

```python
from __future__ import annotations

import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_bacnet_sc import OTBacnetSc


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_ot_bacnet_sc_unreachable():
    port = _free_port()
    probe = OTBacnetSc()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host="127.0.0.1", port=port, proto_hint="bacnet_sc")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) == 1
    assert findings[0].evidence.get("reachable") is False
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_bacnet_sc.py`:

```python
"""ot.bacnet_sc.tls — BACnet Secure Connect TLS handshake."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTBacnetSc(Probe):
    id = "ot.bacnet_sc.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "bacnet_sc") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "bacnet_sc")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=47808, proto_hint="bacnet_sc")]
        for target in targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=2.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_bacnet_sc.py -v
git add src/pqcscan/probes/ot_bacnet_sc.py tests/probes/test_ot_bacnet_sc.py
git commit -m "feat(probes): ot.bacnet_sc.tls — BACnet Secure Connect TLS (Plan H.3b)"
```

### Task 4.5: Register H.3b probes + tag v0.4.1

**Files:**
- Modify: `src/pqcscan/probes/_registry.py`
- Modify: `src/pqcscan/compliance/frameworks/nacsa-arahan-ke-9.yaml`
- Modify: `docs/STATUS.md`, `README.md`

- [ ] **Step 1: Add 4 imports + adds**

```python
from pqcscan.probes.ot_opc_ua import OTOpcUa
from pqcscan.probes.ot_cip_security import OTCipSecurity
from pqcscan.probes.ot_bacnet import OTBacnet
from pqcscan.probes.ot_bacnet_sc import OTBacnetSc
```

```python
reg.add(OTOpcUa())
reg.add(OTCipSecurity())
reg.add(OTBacnet())
reg.add(OTBacnetSc())
```

- [ ] **Step 2: Verify count = 110**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"
```

- [ ] **Step 3: Extend NACSA YAML for OPC UA deprecated policies**

Append to `nacsa-arahan-ke-9.yaml`:

```yaml
  - match: { probe_id_prefix: ot.opc_ua, algorithm: Basic128Rsa15 }
    clause: NACSA-9:opcua-deprecated
    verdict: non-compliant
    note: "OPC UA Basic128Rsa15 menggunakan SHA-1 + RSA-PKCS#1 v1.5 (terlarang)."

  - match: { probe_id_prefix: ot.opc_ua, algorithm: Basic256 }
    clause: NACSA-9:opcua-deprecated
    verdict: non-compliant
    note: "OPC UA Basic256 (SHA-1) terlarang. Gunakan Basic256Sha256 atau lebih baik."
```

- [ ] **Step 4: STATUS + README + tag**

```bash
git add src/pqcscan/probes/_registry.py \
        src/pqcscan/compliance/frameworks/nacsa-arahan-ke-9.yaml \
        docs/STATUS.md README.md
git commit -m "feat(registry,compliance,docs): Plan H.3b — OPC UA + CIP Sec + BACnet + BACnet/SC (110 probes)"
git tag -a v0.4.1 -m "Plan H.3b — OT TLS-wrapped + OPC UA SecurityPolicy classification (4 probes)"
```

---

## Phase 3c — H.3c: Telco / health / IoT (target tag v0.4.2)

### Task 5.1: ot.gtp.cu probe (UDP echo)

**Files:**
- Create: `src/pqcscan/probes/ot_gtp.py`
- Test: `tests/probes/test_ot_gtp.py`

- [ ] **Step 1: Test**

`tests/probes/test_ot_gtp.py`:

```python
from __future__ import annotations

import asyncio
import socket
from typing import Any

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_gtp import OTGtp


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def gtp_server():
    port = _free_udp_port()
    loop = asyncio.get_running_loop()

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport: Any) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Any) -> None:
            resp = bytes.fromhex("4802000400000001")
            if self.transport:
                self.transport.sendto(resp, addr)

    transport, _ = await loop.create_datagram_endpoint(_Proto, local_addr=("127.0.0.1", port))
    try:
        yield "127.0.0.1", port
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_ot_gtp_no_ipsec(gtp_server):
    host, port = gtp_server
    probe = OTGtp()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host=host, port=port, proto_hint="gtp")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
    assert findings[0].evidence.get("plain_gtp") is True
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_gtp.py`:

```python
"""ot.gtp.cu — GTPv2-C / GTPv1-U Echo over UDP/2123 or 2152; flags absence of IPsec."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _gtpv2c_echo() -> bytes:
    return bytes.fromhex("4801000400000001")


class OTGtp(Probe):
    id = "ot.gtp.cu"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "gtp") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "gtp")]
        if not targets:
            targets = [
                OTTarget(host="127.0.0.1", port=2123, proto_hint="gtp"),
                OTTarget(host="127.0.0.1", port=2152, proto_hint="gtp"),
            ]
        for target in targets:
            await self._probe_one(target, emit)

    async def _probe_one(self, target: OTTarget, emit: Emitter) -> None:
        loop = asyncio.get_running_loop()
        future_resp: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: Any) -> None:
                if not future_resp.done():
                    future_resp.set_result(data)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(target.host, target.port),
            )
        except OSError as e:
            emit(Finding(
                probe_id=self.id,
                asset=f"udp://{target.host}:{target.port}",
                severity=Severity.INFO,
                evidence={"reachable": False, "error": repr(e)},
            ))
            return
        try:
            transport.sendto(_gtpv2c_echo())
            try:
                resp = await asyncio.wait_for(future_resp, timeout=2.0)
            except (TimeoutError, asyncio.TimeoutError):
                resp = b""
        finally:
            transport.close()

        gtp_ok = len(resp) >= 1 and (resp[0] >> 5) in (1, 2)
        emit(Finding(
            probe_id=self.id,
            asset=f"udp://{target.host}:{target.port}",
            classification=Classification.INFO,
            severity=Severity.HIGH,
            evidence={
                "transport": "UDP",
                "plain_gtp": gtp_ok,
                "no_crypto": True,
                "ipsec_tunnel_detected_externally": False,
                "response_len": len(resp),
                "note": "Confirm IPsec wrap separately via net.ike.v1v2",
            },
        ))
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_gtp.py -v
git add src/pqcscan/probes/ot_gtp.py tests/probes/test_ot_gtp.py
git commit -m "feat(probes): ot.gtp.cu — plain GTP-C/GTP-U detection (Plan H.3c)"
```

### Task 5.2: ot.dicom.tls probe

**Files:**
- Create: `src/pqcscan/probes/ot_dicom_tls.py`
- Test: `tests/probes/test_ot_dicom_tls.py`

- [ ] **Step 1: Test (unreachable path)**

`tests/probes/test_ot_dicom_tls.py`:

```python
from __future__ import annotations

import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_dicom_tls import OTDicomTls


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_ot_dicom_unreachable():
    port = _free_port()
    probe = OTDicomTls()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host="127.0.0.1", port=port, proto_hint="dicom")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) == 1
    assert findings[0].evidence.get("reachable") is False
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_dicom_tls.py`:

```python
"""ot.dicom.tls — DICOM A-ASSOCIATE-RQ over TLS (port 2762)."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTDicomTls(Probe):
    id = "ot.dicom.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "dicom") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "dicom")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=2762, proto_hint="dicom")]
        for target in targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=2.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_dicom_tls.py -v
git add src/pqcscan/probes/ot_dicom_tls.py tests/probes/test_ot_dicom_tls.py
git commit -m "feat(probes): ot.dicom.tls — DICOM-TLS detection (Plan H.3c)"
```

### Task 5.3: ot.hl7.tls probe

**Files:**
- Create: `src/pqcscan/probes/ot_hl7_tls.py`
- Test: `tests/probes/test_ot_hl7_tls.py`

- [ ] **Step 1: Test (unreachable path)**

`tests/probes/test_ot_hl7_tls.py`:

```python
from __future__ import annotations

import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_hl7_tls import OTHl7Tls


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_ot_hl7_unreachable():
    port = _free_port()
    probe = OTHl7Tls()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host="127.0.0.1", port=port, proto_hint="hl7")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) == 1
    assert findings[0].evidence.get("reachable") is False
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_hl7_tls.py`:

```python
"""ot.hl7.tls — MLLP over TLS (HL7 MLLPS) handshake on port 2575."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTHl7Tls(Probe):
    id = "ot.hl7.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "hl7") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "hl7")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=2575, proto_hint="hl7")]
        for target in targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=2.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    asset=f"tcp://{target.host}:{target.port}",
                    severity=Severity.INFO,
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_hl7_tls.py -v
git add src/pqcscan/probes/ot_hl7_tls.py tests/probes/test_ot_hl7_tls.py
git commit -m "feat(probes): ot.hl7.tls — HL7-MLLP-TLS detection (Plan H.3c)"
```

### Task 5.4: ot.coap.dtls probe

**Files:**
- Create: `src/pqcscan/probes/ot_coap_dtls.py`
- Test: `tests/probes/test_ot_coap_dtls.py`

- [ ] **Step 1: Test (unreachable path)**

`tests/probes/test_ot_coap_dtls.py`:

```python
from __future__ import annotations

import socket

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import OTTarget, ScanContext
from pqcscan.probes.ot_coap_dtls import OTCoapDtls


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_ot_coap_dtls_unreachable():
    port = _free_port()
    probe = OTCoapDtls()
    findings: list[Finding] = []
    ctx = ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        ot_targets=[OTTarget(host="127.0.0.1", port=port, proto_hint="coap_dtls")],
    )
    await probe.run(ctx, findings.append)
    assert len(findings) >= 1
```

- [ ] **Step 2: Implement**

`src/pqcscan/probes/ot_coap_dtls.py`:

```python
"""ot.coap.dtls — DTLS handshake against CoAPS endpoint on UDP/5684."""
from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._dtls_probe import run_dtls_probe


class OTCoapDtls(Probe):
    id = "ot.coap.dtls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "coap_dtls") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "coap_dtls")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=5684, proto_hint="coap_dtls")]

        for target in targets:
            await run_dtls_probe(
                host=target.host, port=target.port, version="1.2",
                probe_id=self.id, emit=emit,
            )
```

- [ ] **Step 3: Commit**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest tests/probes/test_ot_coap_dtls.py -v
git add src/pqcscan/probes/ot_coap_dtls.py tests/probes/test_ot_coap_dtls.py
git commit -m "feat(probes): ot.coap.dtls — CoAPS DTLS handshake (Plan H.3c)"
```

### Task 5.5: Register H.3c probes + final docs + tag v0.4.2

**Files:**
- Modify: `src/pqcscan/probes/_registry.py`
- Modify: `docs/STATUS.md`, `README.md`
- Modify: `src/pqcscan/ui/templates/probes.html` (only if not auto-iterating)

- [ ] **Step 1: Add 4 imports + adds**

```python
from pqcscan.probes.ot_gtp import OTGtp
from pqcscan.probes.ot_dicom_tls import OTDicomTls
from pqcscan.probes.ot_hl7_tls import OTHl7Tls
from pqcscan.probes.ot_coap_dtls import OTCoapDtls
```

```python
reg.add(OTGtp())
reg.add(OTDicomTls())
reg.add(OTHl7Tls())
reg.add(OTCoapDtls())
```

- [ ] **Step 2: Verify count = 114**

```bash
/tmp/pqcscan-venv311/bin/python -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"
```

- [ ] **Step 3: STATUS + README final update**

Update probe count to 114. Add Plan H.3c row. Update Plan H closeout summary.

- [ ] **Step 4: Probes UI template — verify auto-iteration**

```bash
grep -n "by_family\|ProbeFamily\|family.value" src/pqcscan/ui/templates/probes.html | head
```

If template auto-iterates registry families: skip — OT family appears automatically.
If template hard-codes family list: add OT family card mirroring existing family cards.

- [ ] **Step 5: Smoke-run daemon, click /probes, confirm OT card visible**

```bash
/tmp/pqcscan-venv311/bin/python -m pqcscan daemon --db /tmp/pqcscan-h3c-smoke.db &
sleep 3
curl -sS http://127.0.0.1:8765/probes | grep -i "ot\." | head -5
kill %1
```

Expected: at least one OT probe id appears in HTML output.

- [ ] **Step 6: Final test sweep**

```bash
/tmp/pqcscan-venv311/bin/python -m pytest -q
/tmp/pqcscan-venv311/bin/python -m ruff check src tests
/tmp/pqcscan-venv311/bin/python -m mypy src/pqcscan
```

- [ ] **Step 7: Commit + tag**

```bash
git add src/pqcscan/probes/_registry.py docs/STATUS.md README.md src/pqcscan/ui/templates/probes.html
git commit -m "feat(registry,docs,ui): Plan H.3c — telco/health/IoT OT probes (114 probes total)"
git tag -a v0.4.2 -m "Plan H.3c — OT telco (GTP) + health (DICOM/HL7) + IoT (CoAPS) (4 probes)"
```

---

## Post-flight

### Task 6.1: Push branch + tags

- [ ] **Step 1: Push branch**

```bash
git push -u origin plan-h
```

- [ ] **Step 2: Push tags**

```bash
git push --tags
```

- [ ] **Step 3: Open PR**

Open PR `plan-h` → `dev` (or `main` if project policy). Title: "Plan H — PQC scope sharpening + OT/ICS T4 coverage". Body summarises H.1/H.2/H.3a/H.3b/H.3c sub-batches and lists all 5 tags.

### Task 6.2: Merge + cleanup

- [ ] **Step 1: Wait for CI green** (if CI configured)
- [ ] **Step 2: Merge PR**
- [ ] **Step 3: Delete local + remote branch**

```bash
git checkout dev
git pull
git branch -d plan-h
git push origin --delete plan-h
```

---

## Self-review notes

**Spec coverage check.** Each spec section maps to:
- Spec §1 Overview → Phase split + probe-count progression in this plan.
- Spec §2 Architecture & integration → Task 3.0 (`ProbeFamily.OT`), Task 3.0.1 (`ScanContext.ot_targets`), Task 3.0.2 (`_binary_proto`), Tasks 2.1–2.3 (UDP + DTLS), all phase 3a/b/c registry tasks.
- Spec §3 H.1 YAGNI trim → Phase 1 (Tasks 1.1–1.8).
- Spec §4 H.2 UDP + DTLS → Phase 2 (Tasks 2.1–2.5).
- Spec §5 H.3 OT family → Phase 3a/3b/3c (Tasks 3.0–5.5).
- Spec §6 Compliance YAML extension → Tasks 3.8 (NACSA + BUKUKERJA OT clauses), 4.5 (NACSA OPC UA deprecated rules).
- Spec §7 Testing strategy → every probe task includes TDD test before implementation; CI gate run in Tasks 1.8, 2.5, 3.9, 4.5, 5.5.
- Spec §8 Migration & breaking-change → Tasks 1.7, 2.5 status doc updates document migration.
- Spec §9 Probe-count progression → Tasks 1.5, 2.4, 3.8, 4.5, 5.5 verify counts at each milestone (98 → 99 → 106 → 110 → 114).
- Spec §10 Open issues / future work → out of scope for this plan; deferred to Plan I.
- Spec §11 Implementation plan handoff → this document.

**Placeholder check.** No "TBD"/"TODO"/"fill in" remain. Where one task mirrors another (e.g. Tasks 4.4, 5.2, 5.3 mirror Task 3.2's TLS-wrapper shape), the source task is named explicitly and full code is repeated per task — engineer can implement out of order.

**Type consistency.** Probe class naming: PascalCase `OT<Protocol>` matches existing `Net*`/`Host*` classes. Probe `id` strings use `ot.<protocol>.<aspect>` lowercase-with-dots. `OTTarget` dataclass added once in Task 3.0.1, referenced by all OT probes — same fields throughout (`host`, `port`, `proto_hint`).

**Out-of-spec risk.** Plan touches 11 probe deletions, 16 new probe files, 3 new helper files (`_udp_payloads`, `_dtls_probe`, `_binary_proto`), 1 enum extension (`ProbeFamily.OT`), 1 ScanContext field (`ot_targets`), 2 YAML files (NACSA + BUKUKERJA), 2 doc files (STATUS + README), 1 UI template (conditionally — only if not auto-iterating), 1 fetch script. No store/schema/migration changes. No new top-level subsystems. Within scope of Plan H spec.
