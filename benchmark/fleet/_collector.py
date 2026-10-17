"""Run a fleet collector (`create_app` under uvicorn) on a free loopback port, backed by SQLite or Postgres."""
from __future__ import annotations

import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

import httpx
import uvicorn
from loguru import logger

from pqcscan.daemon.app import create_app
from pqcscan.probes._registry import Registry

ENROLL_TOKEN = "load-enroll-token"
PG_IMAGE = "postgres:16-alpine"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def postgres_container() -> Iterator[str]:
    """Throwaway `postgres:16-alpine`; yields a SQLAlchemy URL and always kills the container."""
    import psycopg

    port = free_port()
    cid = subprocess.run(["docker", "run", "--rm", "-d", "-p", f"127.0.0.1:{port}:5432", "-e", "POSTGRES_PASSWORD=pqc",
                          PG_IMAGE], capture_output=True, text=True, check=True).stdout.strip()
    try:
        deadline = time.monotonic() + 90
        while True:     # initdb's temporary server listens on a unix socket only, so a TCP connect means final server
            try:
                psycopg.connect(f"host=127.0.0.1 port={port} user=postgres password=pqc dbname=postgres",
                                connect_timeout=2).close()
                break
            except psycopg.OperationalError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        yield f"postgresql+psycopg://postgres:pqc@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run(["docker", "kill", cid], capture_output=True)


@contextmanager
def collector(db: str, workdir: Path, enroll_token: str = ENROLL_TOKEN) -> Iterator[str]:
    """Yield the base URL of a running collector; `db` is "sqlite" or "postgres"."""
    if db not in ("sqlite", "postgres"):
        raise ValueError(f"db must be sqlite or postgres, not {db!r}")
    logger.disable("pqcscan")   # one info line per enrolment would drown the run output
    with ExitStack() as stack:
        target = workdir / "fleet.db" if db == "sqlite" else stack.enter_context(postgres_container())
        app = create_app(db_path=target, registry=Registry(), enroll_token=enroll_token)
        port = free_port()
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        stack.callback(t.join, 10)
        stack.callback(setattr, server, "should_exit", True)
        url = f"http://127.0.0.1:{port}"
        for _ in range(200):
            if not t.is_alive():
                raise RuntimeError("uvicorn thread died during startup")
            try:
                if httpx.get(f"{url}/api/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        else:
            raise RuntimeError("collector did not become healthy")
        yield url
