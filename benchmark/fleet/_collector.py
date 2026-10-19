"""Run a fleet collector (`create_app` under uvicorn) on a free loopback port, backed by SQLite or Postgres."""
from __future__ import annotations

import asyncio
import collections
import gzip
import json
import logging
import re
import shutil
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
from sqlalchemy import event

from pqcscan.daemon.app import create_app
from pqcscan.probes._registry import Registry

ENROLL_TOKEN = "load-enroll-token"
PG_IMAGE = "postgres:16-alpine"
PG_PROFILE_FLAGS = ("-c", "shared_preload_libraries=pg_stat_statements", "-c", "pg_stat_statements.track=all",
                    "-c", "session_preload_libraries=auto_explain", "-c", "auto_explain.log_min_duration=0",
                    "-c", "auto_explain.log_analyze=on", "-c", "auto_explain.log_buffers=on",
                    "-c", "auto_explain.sample_rate=0.02", "-c", "auto_explain.log_parameter_max_length=0")
PG_TOP_SQL = ("SELECT calls, total_exec_time, mean_exec_time, rows, left(query, 200) FROM pg_stat_statements "
              "WHERE query NOT ILIKE '%pg_stat_statements%' ORDER BY total_exec_time DESC LIMIT 25")
PG_SUM_SQL = "SELECT sum(calls) FROM pg_stat_statements WHERE query NOT ILIKE '%pg_stat_statements%'"
SLOW_LOG_MARKER = "# asyncio slow-callback log, threshold 0.1 s"
LAST_PG_CONTAINER: str | None = None     # id of the last profiled Postgres container, for the auto_explain log dump


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def postgres_container(profile: bool = False) -> Iterator[str]:
    """Throwaway `postgres:16-alpine`; yields a SQLAlchemy URL and always kills the container. `profile` starts the
    server with pg_stat_statements and auto_explain (every statement, analysed)
    and keeps the id in LAST_PG_CONTAINER."""
    global LAST_PG_CONTAINER
    import psycopg

    port = free_port()
    cid = subprocess.run(["docker", "run", "--rm", "-d", "-p", f"127.0.0.1:{port}:5432", "-e", "POSTGRES_PASSWORD=pqc",
                          PG_IMAGE, *(PG_PROFILE_FLAGS if profile else ())],
                         capture_output=True, text=True, check=True).stdout.strip()
    if profile:
        LAST_PG_CONTAINER = cid
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
        if profile:
            with psycopg.connect(f"host=127.0.0.1 port={port} user=postgres password=pqc dbname=postgres",
                                 autocommit=True) as c:
                c.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        yield f"postgresql+psycopg://postgres:pqc@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run(["docker", "kill", cid], capture_output=True)


_QUOTED = re.compile(r"'(?:[^']|'')*'?")      # closing quote optional: a key may end inside a literal
_DIGITS = re.compile(r"\d+")


def _norm(sql: str) -> str:
    """Statement shape for counting: quoted strings and digit runs become ?, whitespace collapses, 120 chars kept."""
    return " ".join(_DIGITS.sub("?", _QUOTED.sub("?", sql[:200])).split())[:120]


def _write_statements(out: Path, source: str, total: int, top: list[dict]) -> None:
    out.write_text(json.dumps({"source": source, "total_statements": total, "top": top}, indent=2) + "\n")


def _pg_statements(url: str, out: Path) -> None:
    """pg_stat_statements totals for the run, read before the container dies."""
    import psycopg

    with psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://")) as c:
        rows = c.execute(PG_TOP_SQL).fetchall()
        total = c.execute(PG_SUM_SQL).fetchone()[0]
    _write_statements(out, "pg_stat_statements", int(total or 0),
                      [{"sql": q, "count": calls, "total_exec_ms": round(tot, 1), "mean_exec_ms": round(mean, 3),
                        "rows": n} for calls, tot, mean, n, q in rows])


def _pg_logs(out: Path) -> None:
    """The profiled container's log (auto_explain plans), streamed into a gzip file before the kill."""
    with gzip.open(out, "wb") as gz:
        p = subprocess.Popen(["docker", "logs", str(LAST_PG_CONTAINER)], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        shutil.copyfileobj(p.stdout, gz)
        p.wait()


def _profile_hooks(stack: ExitStack, app, profile_dir: Path) -> None:
    """asyncio slow callbacks (>= 100 ms) to asyncio-slow.log; SQLite statements counted by the sqlite3 trace
    callback into statements.json on exit."""
    profile_dir.mkdir(parents=True, exist_ok=True)

    log = profile_dir / "asyncio-slow.log"
    fh = logging.FileHandler(log, mode="a", delay=True)
    fh.setLevel(logging.WARNING)
    aio = logging.getLogger("asyncio")

    async def _debug() -> None:
        loop = asyncio.get_running_loop()
        loop.set_debug(True)
        loop.slow_callback_duration = 0.1
        # Attached here, at server startup: uvicorn.Config's dictConfig closes every handler that exists when the
        # config is built. The marker tells "0 slow callbacks" (marker only) from "not captured" (empty or absent).
        log.write_text(SLOW_LOG_MARKER + "\n")                # a reused dir holds one run
        aio.addHandler(fh)

    app.router.add_event_handler("startup", _debug)
    stack.callback(fh.close)
    stack.callback(aio.removeHandler, fh)
    engine = app.state.repo.engine
    if engine.dialect.name != "sqlite":
        return
    counts: collections.Counter[str] = collections.Counter()
    lock = threading.Lock()          # sync endpoints run in a thread pool: the callback fires from many threads

    def _count(sql: str) -> None:     # its frames are reported apart as _profile.instrumentation_pct
        # The callback gets every expanded statement (each executemany row, literals and all): keep it to a slice
        # and a counter bump, and normalise once per distinct key at dump time. Cutting at VALUES gives every row
        # of an insert one key; other statements keep 200 chars.
        key = sql.partition(" VALUES ")[0][:200]
        with lock:
            counts[key] += 1

    def _dump() -> None:
        shapes: collections.Counter[str] = collections.Counter()
        for raw, n in counts.items():
            shapes[_norm(raw)] += n
        _write_statements(profile_dir / "statements.json", "sqlite3 trace callback", sum(shapes.values()),
                          [{"sql": q, "count": n} for q, n in shapes.most_common(25)])

    @event.listens_for(engine, "connect")
    def _trace(dbapi_conn, _rec) -> None:
        if hasattr(dbapi_conn, "set_trace_callback"):
            dbapi_conn.set_trace_callback(_count)

    engine.dispose()                 # connections pooled during create_app predate the listener: reopen them
    stack.callback(_dump)


@contextmanager
def collector(db: str, workdir: Path, enroll_token: str = ENROLL_TOKEN,
              profile_dir: Path | None = None, ingest_parallelism: int | None = None,
              insert_mode: str | None = None, info: dict | None = None) -> Iterator[str]:
    """Yield the base URL of a running collector; `db` is "sqlite" or "postgres". `profile_dir` turns on the
    profile hooks (asyncio slow callbacks, statement counts, Postgres auto_explain log). `ingest_parallelism` goes to
    `create_app` (None: its per-dialect default). `insert_mode` picks the bulk-insert strategy: "pages" (multi-row
    INSERT ... VALUES, the product default on SQLite) or "executemany" (one parameter set per row, the product default
    on Postgres); None leaves the product default. `info`, when given, receives the resolved `ingest_parallelism`
    and `insert_mode`."""
    if db not in ("sqlite", "postgres"):
        raise ValueError(f"db must be sqlite or postgres, not {db!r}")
    if insert_mode not in (None, "pages", "executemany"):
        raise ValueError(f"insert_mode must be pages or executemany, not {insert_mode!r}")
    logger.disable("pqcscan")   # one info line per enrolment would drown the run output
    with ExitStack() as stack:
        stack.callback(logger.enable, "pqcscan")     # callbacks run last-in first-out: this is the final step
        if db == "sqlite":
            target = workdir / "fleet.db"
        else:
            target = stack.enter_context(postgres_container(profile=profile_dir is not None))
            if profile_dir:                          # registered after the container: run before its kill
                stack.callback(_pg_logs, profile_dir / "auto_explain.log.gz")
                stack.callback(_pg_statements, target, profile_dir / "statements.json")
        app = create_app(db_path=target, registry=Registry(), enroll_token=enroll_token,
                         ingest_parallelism=ingest_parallelism)
        dialect = app.state.repo.engine.dialect
        if insert_mode is not None:
            dialect.use_insertmanyvalues_wo_returning = insert_mode == "pages"
        if info is not None:
            info["ingest_parallelism"] = app.state.ingest_parallelism
            info["insert_mode"] = "pages" if dialect.use_insertmanyvalues_wo_returning else "executemany"
        if profile_dir:                              # registered before the server: dumps run after it stops
            _profile_hooks(stack, app, profile_dir)
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
