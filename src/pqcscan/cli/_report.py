"""Report a finished scan to the fleet daemon (enroll once, POST the bundle, spool on failure)."""
from __future__ import annotations

import contextlib
import ipaddress
import os
import ssl
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from loguru import logger

from pqcscan.store.bundle import HostIdentity, dump_bundle
from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path

TOKEN_FILE = "agent.token"
SPOOL_DIR = "spool"
REJECTED_DIR = "rejected"
# The collector will never accept these bundles: do not spool or retry them.
PERMANENT_REJECTS = frozenset({400, 403, 413})


class ReportError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class PermanentRejectError(ReportError):
    """The ingest endpoint refused this bundle for good (400/403/413). Enroll-time errors never use this."""


def default_state_dir(db: Path | str | None = None) -> Path:
    """<db dir>/agent for a file --db; the default DB's directory for a URL or no --db."""
    return (db if isinstance(db, Path) else default_db_path()).parent / "agent"


def make_client(*, ca_cert: Path | None = None, insecure: bool = False, timeout: float = 60.0) -> httpx.Client:
    verify: bool | ssl.SSLContext = True
    if insecure:
        verify = False
    elif ca_cert:
        verify = ssl.create_default_context(cafile=str(ca_cert))
    return httpx.Client(verify=verify, timeout=timeout, follow_redirects=False)


def check_server_scheme(server: str, allow_http: bool) -> None:
    """Refuse to send agent credentials in clear text unless https, loopback, or explicitly allowed."""
    parts = urlsplit(server)
    host = parts.hostname or ""
    if parts.scheme == "https" or allow_http or host == "localhost":
        return
    with contextlib.suppress(ValueError):
        if ipaddress.ip_address(host).is_loopback:
            return
    raise ReportError(0, f"refusing to send agent credentials over plain http to {host or server}; "
                         "use https or --allow-http")


def _write_private(path: Path, data: bytes | str, mode: int, *, exclusive: bool = False) -> None:
    """Write a secret file without following symlinks; never loosens an existing parent directory."""
    created = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if created:
        with contextlib.suppress(OSError):
            os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as fh:
        with contextlib.suppress(AttributeError, OSError):   # no fchmod on Windows
            os.fchmod(fd, mode)                              # tighten before the secret is written
        fh.write(data.encode() if isinstance(data, str) else data)
    try:
        os.chmod(path, mode)
    except OSError as e:
        with contextlib.suppress(OSError):
            path.unlink()
        raise ReportError(0, f"cannot secure token file {path}: {e}") from e


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
    except (httpx.HTTPError, httpx.InvalidURL) as e:
        raise ReportError(0, f"enroll failed: {e}") from e
    _raise_for(r)
    try:
        tok = str(r.json()["agent_token"])
    except (ValueError, KeyError, TypeError) as e:
        raise ReportError(0, f"enroll: malformed response ({type(e).__name__}: {e})") from e
    if not tok:
        raise ReportError(0, "enroll: empty agent token in response")
    try:
        _write_private(token_path, tok, 0o600)
    except OSError as e:
        raise ReportError(0, f"cannot write token file {token_path}: {e}") from e
    return tok


def post_bundle(server: str, token: str, data: bytes, client: httpx.Client) -> dict:
    try:
        r = client.post(server.rstrip("/") + "/api/ingest", content=data,
                        headers={"authorization": f"Bearer {token}", "content-type": "application/gzip"})
    except (httpx.HTTPError, httpx.InvalidURL) as e:
        raise ReportError(0, f"ingest failed: {e}") from e
    _raise_for(r)
    try:
        body = r.json()
        if not isinstance(body, dict):
            raise TypeError(f"expected a JSON object, got {type(body).__name__}")
        return dict(body)
    except (ValueError, TypeError) as e:
        raise ReportError(0, f"ingest: malformed response ({type(e).__name__}: {e})") from e


def spool_bundle(state_dir: Path, data: bytes) -> Path:
    # Names sort chronologically, so replay is oldest-first and the newest scan stays the host's latest.
    p = state_dir / SPOOL_DIR / f"{time.time_ns():020d}-{uuid.uuid4().hex}.bundle.gz"
    _write_private(p, data, 0o600, exclusive=True)
    return p


def _quarantine(p: Path) -> None:
    dest = p.parent / REJECTED_DIR
    dest.mkdir(mode=0o700, exist_ok=True)
    os.replace(p, dest / p.name)


def flush_spool(server: str, token: str, state_dir: Path, client: httpx.Client) -> tuple[int, int, int]:
    """Send spooled bundles oldest-first; returns (sent, kept, rejected).

    Permanently rejected files move to spool/rejected/ and flushing continues."""
    sent = kept = rejected = 0
    spool = state_dir / SPOOL_DIR
    if not spool.is_dir():
        return sent, kept, rejected
    for p in sorted(spool.glob("*.bundle.gz")):
        try:
            post_bundle(server, token, p.read_bytes(), client)
        except OSError as e:
            logger.warning("fleet: cannot read spool {} ({}), left in place", p.name, e)
            kept += 1
            continue
        except ReportError as e:
            if e.status in PERMANENT_REJECTS:
                try:
                    _quarantine(p)
                except OSError as qe:
                    logger.warning("fleet: spool {} rejected ({}) but cannot move it ({})", p.name, e.status, qe)
                    kept += 1
                else:
                    logger.warning("fleet: spool {} rejected ({}), moved to {}/", p.name, e.status, REJECTED_DIR)
                    rejected += 1
                continue
            kept += 1
            if e.status in (0, 401, 429) or e.status >= 500:
                break                            # server down, throttling or token rejected: stop this pass
            continue
        sent += 1
        try:
            p.unlink(missing_ok=True)
        except OSError as e:                     # sent already; the server dedups a later resend
            logger.warning("fleet: sent spool {} but cannot remove it ({})", p.name, e)
    return sent, kept, rejected


def report_scan(repo: Repo, scan_id: int, *, server: str, enroll_token: str | None, agent_token: str | None,
                labels: dict[str, str], state_dir: Path, client: httpx.Client,
                allow_http: bool = False, on_reenroll: Callable[[], None] | None = None) -> dict | None:
    """Dump, enroll if needed, flush the spool, POST. Once the bundle exists, any failure spools it,
    except a permanent ingest rejection (400/403/413), which raises PermanentRejectError.

    on_reenroll is called when a rejected stored token is dropped and a fresh enroll is attempted."""
    from pqcscan.util.hostid import host_identity
    check_server_scheme(server, allow_http)      # config error: raise before dumping, nothing to spool
    identity = host_identity(labels)
    data = dump_bundle(repo, scan_id, identity)

    def send() -> dict:
        token = agent_token or ensure_agent_token(server, enroll_token=enroll_token, identity=identity,
                                                  state_dir=state_dir, client=client)
        flush_spool(server, token, state_dir, client)
        try:
            return post_bundle(server, token, data, client)
        except ReportError as e:
            if e.status in PERMANENT_REJECTS:
                raise PermanentRejectError(e.status, f"{e.detail} (permanent rejection)") from e
            raise

    try:
        try:
            return send()
        except ReportError as e:
            if e.status != 401 or agent_token:   # only a stored token is ours to replace
                raise
            token_path = state_dir / TOKEN_FILE
            if not enroll_token:
                raise ReportError(401, f"agent token rejected; re-run with --enroll-token or delete {token_path}"
                                  ) from e
            logger.warning("fleet: agent token rejected by {}; re-enrolling", server)
            token_path.unlink(missing_ok=True)
            if on_reenroll:
                on_reenroll()
            return send()                        # once: a second 401 spools like any failure
    except Exception as e:  # a dumped bundle must never be lost
        if isinstance(e, PermanentRejectError):
            raise                                # retrying can never succeed; scan.py says "not spooled"
        try:
            p = spool_bundle(state_dir, data)
        except Exception as spool_err:
            raise ReportError(0, f"{e}; cannot spool to {state_dir}: {spool_err}") from spool_err
        logger.warning("fleet: report to {} failed ({}); spooled {}", server, e, p)
        return None
