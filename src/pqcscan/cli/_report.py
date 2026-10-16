"""Report a finished scan to the fleet daemon (enroll once, POST the bundle, spool on failure)."""
from __future__ import annotations

import contextlib
import os
import uuid
from pathlib import Path

import httpx
from loguru import logger

from pqcscan.store.bundle import HostIdentity, dump_bundle
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path

TOKEN_FILE = "agent.token"
SPOOL_DIR = "spool"


class ReportError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


def default_state_dir() -> Path:
    return default_db_path().parent / "agent"


def make_client(*, ca_cert: Path | None = None, insecure: bool = False, timeout: float = 60.0) -> httpx.Client:
    verify: bool | str = False if insecure else (str(ca_cert) if ca_cert else True)
    return httpx.Client(verify=verify, timeout=timeout, follow_redirects=False)


def _write_private(path: Path, data: bytes | str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data.encode() if isinstance(data, str) else data)
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


def _raise_for(r: httpx.Response) -> None:
    if r.status_code // 100 != 2:
        try:
            detail = str(r.json().get("detail", r.text))
        except (ValueError, AttributeError):
            detail = r.text
        raise ReportError(r.status_code, detail)


def ensure_agent_token(server: str, *, enroll_token: str | None, identity: HostIdentity,
                       state_dir: Path, client: httpx.Client) -> str:
    token_path = state_dir / TOKEN_FILE
    if token_path.is_file():
        tok = token_path.read_text().strip()
        if tok:
            return tok
    if not enroll_token:
        raise ReportError(0, f"no agent token at {token_path} and no --enroll-token given")
    try:
        r = client.post(server.rstrip("/") + "/api/agents/enroll", json={
            "enroll_token": enroll_token,
            "host": {"machine_id": identity.machine_id, "hostname": identity.hostname, "os": identity.os,
                     "labels": identity.labels, "agent_version": identity.agent_version},
        })
    except httpx.HTTPError as e:
        raise ReportError(0, f"enroll failed: {e}") from e
    _raise_for(r)
    tok = str(r.json()["agent_token"])
    _write_private(token_path, tok, 0o600)
    return tok


def post_bundle(server: str, token: str, data: bytes, client: httpx.Client) -> dict:
    try:
        r = client.post(server.rstrip("/") + "/api/ingest", content=data,
                        headers={"authorization": f"Bearer {token}", "content-type": "application/gzip"})
    except httpx.HTTPError as e:
        raise ReportError(0, f"ingest failed: {e}") from e
    _raise_for(r)
    return dict(r.json())


def spool_bundle(state_dir: Path, data: bytes) -> Path:
    p = state_dir / SPOOL_DIR / f"{uuid.uuid4()}.bundle.gz"
    _write_private(p, data, 0o600)
    return p


def flush_spool(server: str, token: str, state_dir: Path, client: httpx.Client) -> tuple[int, int]:
    sent = kept = 0
    spool = state_dir / SPOOL_DIR
    if not spool.is_dir():
        return sent, kept
    for p in sorted(spool.glob("*.bundle.gz")):
        try:
            post_bundle(server, token, p.read_bytes(), client)
        except ReportError as e:
            if e.status in (400, 403, 413):      # will never succeed; keep for inspection, don't retry forever
                logger.warning("fleet: spool {} rejected ({}), left in place", p.name, e.status)
            kept += 1
            if e.status in (0, 429) or e.status >= 500:
                break                            # server down or throttling: stop this pass
            continue
        p.unlink(missing_ok=True)
        sent += 1
    return sent, kept


def report_scan(repo: Repo, scan_id: int, *, server: str, enroll_token: str | None, agent_token: str | None,
                labels: dict[str, str], state_dir: Path, client: httpx.Client) -> dict | None:
    from pqcscan.util.hostid import host_identity
    identity = host_identity(labels)
    data = dump_bundle(repo, scan_id, identity)
    try:
        token = agent_token or ensure_agent_token(server, enroll_token=enroll_token, identity=identity,
                                                  state_dir=state_dir, client=client)
        flush_spool(server, token, state_dir, client)
        return post_bundle(server, token, data, client)
    except ReportError as e:
        p = spool_bundle(state_dir, data)
        logger.warning("fleet: report to {} failed ({}); spooled {}", server, e, p)
        return None
