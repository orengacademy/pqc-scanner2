"""SIMULATED fleet soak: many agent state dirs on this one box, compressed cycles, injected faults.

    python -m benchmark.fleet.soak --db sqlite|postgres --hosts 30 --cycles 7 --interval 60 --fault-plan default
    python -m benchmark.fleet.soak --render results/soak-simulated-sqlite-<date>.json ...   # markdown tables

Each simulated host has its own state dir, its own machine id (`PQCSCAN_TEST_MACHINE_ID=m-soak-NNN`), three
labels and a small fixture dir with one weak certificate. Every cycle runs the REAL `pqcscan agent --once`
subprocess for every host against a real collector (`create_app` under uvicorn, SQLite or Postgres), so the
spool, token, enrolment, ingest, drift and retention code is the product's own. The harness only starts and stops
the collector, calls `pqcscan agents revoke|unrevoke`, swaps one host's `--path`, and re-posts one bundle.

What is simulated, and what is not: see benchmark/fleet/SOAK.md. The real 30-host, 7-day run is soak-real.md.
Note the agent scans the whole box (host probes), not only `--path`, so every host reports ~1,700 findings and one
scan takes 10 to 20 s of CPU. A cycle therefore starts at `max(previous start + interval, previous end)`.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import uvicorn
from loguru import logger

from pqcscan.daemon.app import create_app
from pqcscan.probes._registry import Registry

from . import _collector
from .run_load import _dirty_files, _git, _load, _src_hash

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SRC = str(REPO / "src")
RESULTS = HERE / "results"
PY = sys.executable
DOWN_CYCLES = {2}  # collector stopped for the whole cycle
REVOKE = {"host": 5, "after": 3, "unrevoke_after": 5}  # applied at the END of the named cycle
CHANGE_PATH = {"host": 7, "at": 4}  # applied at the START of the cycle
REPLAY = {"host": 9, "after": 6}  # applied at the END of the cycle
N_LABELS = 3


def machine(h: int) -> str:
    return f"m-soak-{h:03d}"


# --- fixtures ---------------------------------------------------------------------------------------------------
def weak_cert_pem(cn: str) -> bytes:
    """Self-signed RSA-1024 cert, valid a year so cert-expiry text does not change between cycles."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


# --- collector with a tap ---------------------------------------------------------------------------------------
class Tap:
    """Pure-ASGI tap around the daemon app: records status and JSON of every ingest and enrol call.

    It maps each agent token to its machine id from the enrol exchange, so a 401 from a revoked token is still
    attributed to its host. It does not change what the app does."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.cycle = 0
        self.injected = False
        self._tokens: dict[str, str] = {}
        self._lock = threading.Lock()

    def wrap(self, app):
        async def tapped(scope, receive, send):
            path = scope.get("path")
            if scope["type"] != "http" or path not in ("/api/ingest", "/api/agents/enroll"):
                return await app(scope, receive, send)
            hdrs = dict(scope["headers"])
            bearer = hdrs.get(b"authorization", b"").decode()[7:].strip()
            req, resp, status = bytearray(), bytearray(), [0]
            t0 = time.monotonic()

            async def rcv():
                m = await receive()
                if m["type"] == "http.request" and path.endswith("enroll"):
                    req.extend(m.get("body", b""))
                return m

            async def snd(m):
                if m["type"] == "http.response.start":
                    status[0] = m["status"]
                elif m["type"] == "http.response.body":
                    resp.extend(m.get("body", b""))
                await send(m)

            try:
                await app(scope, rcv, snd)
            finally:
                self._record(path, status[0] or 500, bearer, bytes(req), bytes(resp), time.monotonic() - t0)

        return tapped

    def _record(self, path: str, status: int, bearer: str, req: bytes, resp: bytes, secs: float) -> None:
        try:
            body = json.loads(resp) if resp else {}
        except ValueError:
            body = {}
        who = None
        with self._lock:
            if path.endswith("enroll"):
                try:
                    who = json.loads(req)["host"]["machine_id"]
                except (ValueError, KeyError, TypeError):
                    who = None
                if status == 201 and who:
                    self._tokens[body.get("agent_token", "")] = who
            else:
                who = self._tokens.get(bearer)
            self.events.append(
                {
                    "cycle": self.cycle,
                    "injected": self.injected,
                    "path": "enroll" if path.endswith("enroll") else "ingest",
                    "status": status,
                    "machine": who,
                    "ms": round(secs * 1000),
                    "scan_id": body.get("scan_id"),
                    "duplicate": body.get("duplicate"),
                    "drift": body.get("drift"),
                    "stored_findings": body.get("stored_findings"),
                    "detail": body.get("detail"),
                }
            )


class Collector:
    """A restartable collector on a fixed port, so a stopped cycle looks like 'connection refused'."""

    def __init__(self, target: Path | str, tap: Tap, keep: int) -> None:
        self.target, self.tap, self.keep = target, tap, keep
        self.port = _collector.free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.log: list[str] = []
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._sink = logger.add(lambda m: self.log.append(str(m).rstrip()), level="INFO", format="{level}: {message}")

    def start(self) -> None:
        app = create_app(
            db_path=self.target,
            registry=Registry(),
            enroll_token=_collector.ENROLL_TOKEN,
            keep_scans_per_host=self.keep,
        )
        self._server = uvicorn.Server(
            uvicorn.Config(self.tap.wrap(app), host="127.0.0.1", port=self.port, log_level="warning")
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        for _ in range(200):
            if not self._thread.is_alive():
                raise RuntimeError("uvicorn thread died during startup")
            try:
                if httpx.get(f"{self.url}/api/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        raise RuntimeError("collector did not become healthy")

    def close(self) -> None:
        self.stop()
        logger.remove(self._sink)         # only our sink: other code in the process keeps its own

    def stop(self) -> None:
        if self._server and self._thread:
            self._server.should_exit = True
            self._thread.join(30)
            if self._thread.is_alive():
                raise RuntimeError("collector did not stop")
        self._server = self._thread = None


# --- one simulated host -----------------------------------------------------------------------------------------
class Sim:
    def __init__(self, work: Path, hosts: int, url: str) -> None:
        self.work, self.hosts, self.url = work, hosts, url
        self.path = {h: work / "fixtures" / f"h{h:03d}" for h in range(1, hosts + 1)}
        for h, p in self.path.items():
            p.mkdir(parents=True)
            (p / "server.pem").write_bytes(weak_cert_pem(f"weak-h{h:03d}.example"))

    def state(self, h: int) -> Path:
        return self.work / "state" / f"h{h:03d}"

    def swap_path(self, h: int) -> None:
        alt = self.work / "fixtures" / f"h{h:03d}-alt"
        alt.mkdir()
        (alt / "server.pem").write_bytes(weak_cert_pem(f"weak-h{h:03d}-changed.example"))
        self.path[h] = alt

    def run_agent(self, h: int) -> dict[str, Any]:
        cmd = [
            PY,
            "-m",
            "pqcscan",
            "agent",
            "--once",
            "--server",
            self.url,
            "--enroll-token",
            _collector.ENROLL_TOKEN,
            "--state-dir",
            str(self.state(h)),
            "--path",
            str(self.path[h]),
            "--allow-http",
            "--labels",
            f"group=g{h % 5},site=s{h % 3},env=soak",
        ]
        env = {**os.environ, "PYTHONPATH": SRC, "PQCSCAN_TEST_MACHINE_ID": machine(h)}
        t0 = time.monotonic()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
            rc, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = -9, "", "agent timed out after 600 s"
        outcome = (
            "reported"
            if "reported" in out and "spooled" not in err
            else "spooled"
            if "report spooled" in err
            else "rejected"
            if "rejected" in err
            else "crash"
        )
        return {"rc": rc, "outcome": outcome, "secs": round(time.monotonic() - t0, 1), "stderr": err.strip()}

    def depth(self, h: int, sub: str = "") -> int:
        d = self.state(h) / "spool" / sub
        return len(list(d.glob("*.bundle.gz"))) if d.is_dir() else 0


# --- the model of what FLEET.md predicts -----------------------------------------------------------------------
def model(hosts: int, cycles: int, faults: bool, keep: int) -> dict[tuple[int, int], dict[str, Any]]:
    """Expected per (cycle, host) observation, derived from the FLEET.md sentences cited in `CHECKS`."""
    st = {h: {"stored": 0, "spool": 0, "token": False, "revoked": False} for h in range(1, hosts + 1)}
    out: dict[tuple[int, int], dict[str, Any]] = {}
    for c in range(1, cycles + 1):
        for h, s in st.items():
            e = {
                "rc": 0,
                "outcome": "reported",
                "ok200": 0,
                "dup": 0,
                "s401": 0,
                "s429": 0,
                "s503": 0,
                "other": 0,
                "enroll201": 0,
                "enroll403": 0,
                "pruned": 0,
                "rejected": 0,
                "drift_pos": faults and (c, h) == (CHANGE_PATH["at"], CHANGE_PATH["host"]),
            }
            if faults and c in DOWN_CYCLES:
                e["outcome"], s["spool"] = "spooled", s["spool"] + 1
            else:
                if not s["token"]:
                    if s["revoked"]:
                        e["enroll403"] += 1
                    else:
                        e["enroll201"] += 1
                        s["token"] = True
                if not s["token"]:
                    e["outcome"], s["spool"] = "spooled", s["spool"] + 1
                elif s["revoked"]:
                    e["s401"] += 2 if s["spool"] else 1
                    s["token"], e["enroll403"], e["outcome"], s["spool"] = False, 1, "spooled", s["spool"] + 1
                else:
                    sent = s["spool"] + 1
                    e["ok200"], s["spool"] = sent, 0
                    s["stored"] += sent
                    e["pruned"] = max(0, s["stored"] - keep)
                    s["stored"] -= e["pruned"]
            e["spool"], e["scans"] = s["spool"], s["stored"]
            out[(c, h)] = e
            if faults and h == REVOKE["host"] and c == REVOKE["after"]:
                s["revoked"] = True
            if faults and h == REVOKE["host"] and c == REVOKE["unrevoke_after"]:
                s["revoked"] = False
    return out


# --- the run ----------------------------------------------------------------------------------------------------
def _db_state(repo, hosts: int) -> dict[str, Any]:
    """machine id -> {scans stored, labels, drift rows on the newest scan} straight from the collector DB."""
    from sqlalchemy import text

    out: dict[str, Any] = {}
    with repo.engine.connect() as c:
        for hid, mid, labels in c.execute(text("select id, machine_id, labels from hosts")).all():
            n = c.execute(text("select count(*) from scans where host_id = :h"), {"h": hid}).scalar()
            newest = c.execute(text("select max(id) from scans where host_id = :h"), {"h": hid}).scalar()
            drift = (
                c.execute(
                    text("select count(*) from findings where scan_id = :s and probe_id = 'fleet.drift'"), {"s": newest}
                ).scalar()
                if newest
                else 0
            )
            sample = (
                [
                    f"{pid}: {title[:160]}"
                    for pid, title in c.execute(
                        text(
                            "select probe_id, title from findings where scan_id = :s and probe_id = 'fleet.drift' "
                            "order by id limit 6"
                        ),
                        {"s": newest},
                    )
                ]
                if drift
                else []
            )
            labels = json.loads(labels) if isinstance(labels, str) else (labels or {})
            out[mid] = {
                "host_id": hid,
                "scans": n,
                "labels": len(labels),
                "drift_rows_newest": drift,
                "drift_sample": sample,
            }
    return out


def _drift_text(repo, scan_id: int) -> list[str]:
    from sqlalchemy import text

    with repo.engine.connect() as con:
        return [
            f"{t[:160]}"
            for (t,) in con.execute(
                text("select title from findings where scan_id = :s and probe_id = 'fleet.drift' order by id limit 12"),
                {"s": scan_id},
            )
        ]


def _cell(sim: Sim, h: int, c: int, run: dict, ev: list[dict], db: dict, before: dict) -> dict[str, Any]:
    mine = [e for e in ev if e["machine"] == machine(h)]
    ing, enr = [e for e in mine if e["path"] == "ingest"], [e for e in mine if e["path"] == "enroll"]
    new = [e for e in ing if e["status"] == 200 and not e["duplicate"]]
    d = db.get(machine(h), {"scans": 0, "labels": 0, "drift_rows_newest": 0})
    cell = {
        "rc": run["rc"],
        "outcome": run["outcome"],
        "secs": run["secs"],
        "spool": sim.depth(h),
        "rejected": sim.depth(h, "rejected"),
        "scans": d["scans"],
        "labels": d["labels"],
        "ok200": len(new),
        "dup": sum(1 for e in ing if e["duplicate"]),
        "s401": sum(1 for e in ing if e["status"] == 401),
        "s429": sum(1 for e in ing if e["status"] == 429),
        "s503": sum(1 for e in ing if e["status"] == 503),
        "other": sum(1 for e in ing if e["status"] not in (200, 401, 429, 503)),
        "enroll201": sum(1 for e in enr if e["status"] == 201),
        "enroll403": sum(1 for e in enr if e["status"] == 403),
        "enroll_other": sum(1 for e in enr if e["status"] not in (201, 403)),
        "drift": [e["drift"] for e in new],
        "drift_rows_newest": d["drift_rows_newest"],
        "drift_sample": d.get("drift_sample", []),
        "pruned": len(new) - (d["scans"] - before.get(machine(h), 0)),
    }
    if run["stderr"]:
        cell["stderr"] = run["stderr"][-600:]
    return cell


def _mismatches(cell: dict, exp: dict) -> list[str]:
    bad = [
        f"{k}: expected {exp[k]}, saw {cell[k]}"
        for k in (
            "rc",
            "outcome",
            "ok200",
            "dup",
            "s401",
            "s429",
            "s503",
            "other",
            "enroll201",
            "enroll403",
            "pruned",
            "rejected",
            "spool",
            "scans",
        )
        if cell[k] != exp[k]
    ]
    drift = sum(x or 0 for x in cell["drift"])
    if exp["drift_pos"] != (drift > 0):
        bad.append(f"drift: expected {'>0' if exp['drift_pos'] else '0'}, saw {drift}")
    if cell["drift"] and cell["drift_rows_newest"] != cell["drift"][-1]:
        bad.append(f"drift rows in DB {cell['drift_rows_newest']} != ingest drift {cell['drift'][-1]}")
    if cell["enroll_other"]:
        bad.append(f"enroll_other: {cell['enroll_other']}")
    if cell["labels"] != N_LABELS:
        bad.append(f"labels: expected {N_LABELS}, saw {cell['labels']}")
    return bad


def _pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * len(xs)))], 1) if xs else 0.0


def run(
    *,
    db: str,
    hosts: int,
    cycles: int,
    interval: float,
    faults: bool,
    workers: int,
    keep: int,
    record: bool = True,
    command: str = "",
) -> dict[str, Any]:
    if faults and hosts < 9:
        raise ValueError("the default fault plan needs at least 9 hosts")
    from pqcscan.store.bundle import HostIdentity, dump_bundle
    from pqcscan.store.repo import Repo

    started = dt.datetime.now(dt.UTC)
    result: dict[str, Any] = {
        "SIMULATED": "one host, compressed intervals; see soak-real.md for the real run",
        "db": db,
        "hosts": hosts,
        "cycles_planned": cycles,
        "interval_s": interval,
        "fault_plan": "default" if faults else "none",
        "workers": workers,
        "keep_scans_per_host": keep,
        "command": command,
        "started_at": started.isoformat(),
        "commit": _git("rev-parse", "HEAD"),
        "src_hash": _src_hash(("src/pqcscan",)),     # the whole package: the agents run its probes, CLI and runner
        "harness_hash": hashlib.sha256((HERE / "soak.py").read_bytes()).hexdigest(),
        "tree_dirty": bool(_dirty_files()),
        "dirty_files": _dirty_files(),
        "box": {
            "cpus": os.cpu_count(),
            "mem_kb": int(Path("/proc/meminfo").read_text().split()[1]),
            "hostname": os.uname().nodename,
            "load_start": _load(),
        },
        "model": "FLEET.md predictions, see CHECKS",
        "cycles": [],
        "injected": {},
    }
    exp = model(hosts, cycles, faults, keep)
    tap = Tap()
    from contextlib import ExitStack

    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix="fleet-soak-") as td:
        work = Path(td)
        target = work / "fleet.db" if db == "sqlite" else stack.enter_context(_collector.postgres_container())
        col = Collector(target, tap, keep)
        col.start()
        stack.callback(col.close)
        sim = Sim(work, hosts, col.url)
        probe = Repo(target)
        probe.init_schema()
        before = {machine(h): 0 for h in range(1, hosts + 1)}
        next_start = time.monotonic()
        for c in range(1, cycles + 1):
            time.sleep(max(0.0, next_start - time.monotonic()))
            t0 = time.monotonic()
            tap.cycle, n_events = c, len(tap.events)
            if faults and c in DOWN_CYCLES:
                col.stop()
            if faults and c == CHANGE_PATH["at"]:
                sim.swap_path(CHANGE_PATH["host"])
            load = _load()["loadavg_1m"]
            with cf.ThreadPoolExecutor(workers) as pool:
                runs = dict(zip(range(1, hosts + 1), pool.map(sim.run_agent, range(1, hosts + 1)), strict=True))
            if faults and c in DOWN_CYCLES:
                col.start()
            ev = [e for e in tap.events[n_events:] if not e["injected"]]
            dbs = _db_state(probe, hosts)
            cells = {h: _cell(sim, h, c, runs[h], ev, dbs, before) for h in runs}
            for h in cells:      # what drifted, for every drifting ingest (not only the newest scan), while it exists
                found = [e for e in ev if e["machine"] == machine(h) and e["path"] == "ingest" and e.get("drift")]
                if found:
                    cells[h]["drift_by_ingest"] = [
                        {"scan_id": e["scan_id"], "drift": e["drift"], "rows": _drift_text(probe, e["scan_id"])}
                        for e in found
                    ]
            bad = {f"h{h:03d}": m for h in cells if (m := _mismatches(cells[h], exp[(c, h)]))}
            ing = [e for e in ev if e["path"] == "ingest"]
            result["cycles"].append(
                {
                    "cycle": c,
                    "duration_s": round(time.monotonic() - t0, 1),
                    "overran_interval": time.monotonic() - t0 > interval,
                    "loadavg_1m_at_start": load,
                    "collector_down": bool(faults and c in DOWN_CYCLES),
                    "cells": {f"h{h:03d}": v for h, v in cells.items()},
                    "mismatches": bad,
                    "unattributed_events": sum(1 for e in ev if e["machine"] is None),
                    "totals": {
                        k: sum(v[k] for v in cells.values())
                        for k in (
                            "ok200",
                            "dup",
                            "s401",
                            "s429",
                            "s503",
                            "other",
                            "enroll201",
                            "enroll403",
                            "pruned",
                            "spool",
                            "rejected",
                            "scans",
                            "rc",
                        )
                    },
                    "outcomes": {
                        o: sum(1 for v in cells.values() if v["outcome"] == o)
                        for o in ("reported", "spooled", "rejected", "crash")
                    },
                    "drift_rows_total": sum(sum(x or 0 for x in v["drift"]) for v in cells.values()),
                    "drift_rows_by_host": {
                        f"h{h:03d}": sum(x or 0 for x in v["drift"])
                        for h, v in cells.items()
                        if sum(x or 0 for x in v["drift"])
                    },
                    "labels_min_max": [
                        min(v["labels"] for v in cells.values()),
                        max(v["labels"] for v in cells.values()),
                    ],
                    "agent_secs_p50_max": [
                        _pct([v["secs"] for v in cells.values()], 0.5),
                        max(v["secs"] for v in cells.values()),
                    ],
                    "ingest_server_ms_p50_p95": [_pct([e["ms"] for e in ing], 0.5), _pct([e["ms"] for e in ing], 0.95)],
                }
            )
            before = {m: d["scans"] for m, d in dbs.items()}
            # end-of-cycle faults
            if faults and c == REVOKE["after"]:
                result["injected"]["revoke"] = _admin(target, "revoke", dbs[machine(REVOKE["host"])]["host_id"])
            if faults and c == REVOKE["unrevoke_after"]:
                result["injected"]["unrevoke"] = _admin(target, "unrevoke", dbs[machine(REVOKE["host"])]["host_id"])
            if faults and c == REPLAY["after"]:
                result["injected"]["replay"] = _replay(sim, probe, tap, REPLAY["host"], dump_bundle, HostIdentity)
            next_start = t0 + interval
        if faults:
            result["injected"]["duplicate_token_probe"] = _dup_probe(
                sim, tap, REPLAY["host"], dump_bundle, HostIdentity
            )
        fleet = httpx.get(f"{col.url}/api/fleet", timeout=60).json()
        result["final"] = {
            "hosts_in_fleet": len(fleet),
            "db_state": _db_state(probe, hosts),
            "sqlite_bytes": (Path(target).stat().st_size if db == "sqlite" else None),
        }
        result["collector_log_warnings"] = [ln[:400] for ln in col.log if not ln.startswith("INFO")][:300]
        result["collector_log_info_lines"] = sum(1 for ln in col.log if ln.startswith("INFO"))
    result["box"]["load_end"] = _load()
    result["finished_at"] = dt.datetime.now(dt.UTC).isoformat()
    result["ingest_success"] = ingest_success(
        [e for e in tap.events if e["path"] == "ingest" and not e["injected"]]
    )
    result["checks"] = evaluate(result, exp)
    result["anomalies"] = [
        f"cycle {cy['cycle']} {h}: {m}"
        + (f" {cy['cells'][h].get('drift_by_ingest')}" if m.startswith("drift") else "")
        for cy in result["cycles"]
        for h, ms in cy["mismatches"].items()
        for m in ms
    ] + [f"collector log: {ln}" for ln in result["collector_log_warnings"]]
    if record:
        RESULTS.mkdir(exist_ok=True)
        path = RESULTS / f"soak-simulated-{db}-{started:%Y%m%d}.json"
        n = 1
        while path.exists():  # never overwrite an earlier run's record
            n += 1
            path = RESULTS / f"soak-simulated-{db}-{started:%Y%m%d}-{n}.json"
        path.write_text(json.dumps(result, indent=2) + "\n")
        result["result_file"] = path.name
    return result


def ingest_success(ingests: list[dict]) -> dict[str, Any]:
    """Ingest calls that stored or recognised a bundle (200), out of all of them, with every other answer named."""
    ok = sum(1 for e in ingests if e["status"] == 200)
    return {
        "ok": ok,
        "calls": len(ingests),
        "rate": round(ok / len(ingests), 4) if ingests else None,
        "non_200": [
            {"cycle": e["cycle"], "machine": e["machine"], "status": e["status"], "detail": e["detail"]}
            for e in ingests
            if e["status"] != 200
        ],
    }


def _admin(target: Path | str, verb: str, host_id: int) -> dict[str, Any]:
    p = subprocess.run(
        [PY, "-m", "pqcscan", "agents", verb, str(host_id), "--db", str(target)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC},
    )
    return {"host_id": host_id, "rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()[-300:]}


def _post(url: str, token: str, data: bytes) -> tuple[int, dict]:
    r = httpx.post(
        f"{url}/api/ingest",
        content=data,
        headers={"authorization": f"Bearer {token}", "content-type": "application/gzip"},
        timeout=60,
    )
    return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else {})


def _old_bundle(sim: Sim, h: int, dump_bundle, identity_cls) -> tuple[bytes, str, int]:
    """The bundle of host h's second-newest local scan, rebuilt from its agent DB (same scan_uuid as when sent)."""
    import socket

    from pqcscan import __version__
    from pqcscan.store.repo import Repo

    local = Repo(sim.state(h) / "agent.db")
    scans = local.list_scans()
    ident = identity_cls(
        machine_id=machine(h),
        hostname=socket.gethostname(),
        os="linux",
        labels={"group": f"g{h % 5}", "site": f"s{h % 3}", "env": "soak"},
        agent_version=__version__,
    )
    token = (sim.state(h) / "agent.token").read_text().strip()
    return dump_bundle(local, scans[1].id, ident), token, scans[1].id


def _replay(sim: Sim, probe, tap: Tap, h: int, dump_bundle, identity_cls) -> dict[str, Any]:
    data, token, local_id = _old_bundle(sim, h, dump_bundle, identity_cls)
    n_before = _db_state(probe, sim.hosts)[machine(h)]["scans"]
    tap.injected = True
    try:
        code, body = _post(sim.url, token, data)
    finally:
        tap.injected = False
    n_after = _db_state(probe, sim.hosts)[machine(h)]["scans"]
    return {
        "host": h,
        "local_scan_id": local_id,
        "status": code,
        "body": body,
        "scans_before": n_before,
        "scans_after": n_after,
    }


def _dup_probe(sim: Sim, tap: Tap, h: int, dump_bundle, identity_cls) -> dict[str, Any]:
    """Re-post the same bundle until the collector answers 429: does a duplicate spend an ingest token?"""
    data, token, _ = _old_bundle(sim, h, dump_bundle, identity_cls)
    seq = []
    tap.injected = True
    try:
        for _ in range(14):
            code, body = _post(sim.url, token, data)
            seq.append(f"{code}{'/dup' if body.get('duplicate') else ''}")
            if code == 429:
                break
    finally:
        tap.injected = False
    return {
        "host": h,
        "sequence": seq,
        "duplicates_before_429": sum(1 for s in seq if s == "200/dup"),
        "got_429": "429" in seq,
    }


# --- expected vs observed ---------------------------------------------------------------------------------------
def _cells(result, cycles, hosts):
    return [result["cycles"][c - 1]["cells"][f"h{h:03d}"] for c in cycles for h in hosts]


def evaluate(result: dict, exp: dict) -> list[dict[str, Any]]:
    """Expected-vs-observed rows. `ok` is true when every involved (cycle, host) cell matches the FLEET.md model."""
    if result["fault_plan"] == "none":
        return []
    nh, nc = result["hosts"], len(result["cycles"])
    allh, cyc = range(1, nh + 1), result["cycles"]
    rv, ch, rp, at = REVOKE["host"], CHANGE_PATH["host"], REPLAY["host"], CHANGE_PATH["at"]

    def cell(c: int, h: int) -> dict:
        return cyc[c - 1]["cells"][f"h{h:03d}"]

    def good(cs, hs) -> bool:
        return all(not _mismatches(cell(c, h), exp[(c, h)]) for c in cs for h in hs)

    def tot(c: int, k: str) -> int:
        return cyc[c - 1]["totals"][k]

    def over(k: str) -> int:
        return sum(tot(c, k) for c in range(1, nc + 1))

    rep, dup = result["injected"].get("replay", {}), result["injected"].get("duplicate_token_probe", {})
    other_drift = sum(
        n for c in cyc for h, n in c["drift_rows_by_host"].items() if (c["cycle"], h) != (at, f"h{ch:03d}")
    )
    want_prune = [sum(exp[(c, h)]["pruned"] for h in allh) for c in range(1, nc + 1)]
    rows = [
        (
            "baseline, cycle 1",
            good([1], allh),
            f"{nh} hosts enrol (201) and report (200), spool 0, exit 0",
            "The first run enrolls and stores a per-agent token",
            "section 2",
            f"enrolled {tot(1, 'enroll201')}, stored {tot(1, 'ok200')}, spool {tot(1, 'spool')}, "
            f"exit codes summed {over('rc')}",
        ),
        (
            "collector down, cycle 2",
            good([2], allh),
            "every host exits 0 with its bundle spooled (spool 1 each); no call reaches the collector",
            "If the collector is down, the bundle is spooled under `<db dir>/agent/spool/` and sent on the next run. "
            "It exits 0 when the report was sent or spooled for retry",
            "section 2, Deployment recipes",
            f"outcomes {cyc[1]['outcomes']}, spool total {tot(2, 'spool')}, calls that reached the collector "
            f"{tot(2, 'ok200') + tot(2, 'enroll201') + tot(2, 's401')}",
        ),
        (
            "spool drains, cycle 3",
            good([3], allh),
            f"spool back to 0 on every host; {2 * nh} bundles stored (the spooled one and the new one, per host)",
            "... and sent on the next run.",
            "section 2",
            f"spool total {tot(3, 'spool')}, stored {tot(3, 'ok200')}, stored scans per host "
            f"{sorted({cell(3, h)['scans'] for h in allh})}",
        ),
        (
            f"revoke host {rv} at the end of cycle {REVOKE['after']}; cycles 4 and 5",
            good([4, 5], allh),
            f"cycle 4: host {rv} ingest 401, re-enrol 403, bundle spooled, exit 0. Cycle 5: enrol 403, spool 2. "
            f"Other hosts unaffected",
            "A revoked host's ingest gets 401 and its re-enroll gets 403, so its bundles spool and replay after "
            "`agents unrevoke`.",
            "Known limits",
            f"cycle 4 host {rv}: 401 x{cell(4, rv)['s401']}, enrol 403 x{cell(4, rv)['enroll403']}, spool "
            f"{cell(4, rv)['spool']}, exit {cell(4, rv)['rc']}. Cycle 5: enrol 403 x{cell(5, rv)['enroll403']}, spool "
            f"{cell(5, rv)['spool']}. Other hosts stored in cycle 4: {tot(4, 'ok200')} of {nh - 1}",
        ),
        (
            f"unrevoke host {rv} at the end of cycle {REVOKE['unrevoke_after']}; cycle 6",
            good([6], allh),
            f"host {rv} enrols (201), its 2 spooled bundles and the new one are stored (3), spool 0",
            "`pqcscan agents unrevoke <id>` lets it enroll again ... re-enrolls and sends (spooled bundles included).",
            "section 6",
            f"enrol 201 x{cell(6, rv)['enroll201']}, stored {cell(6, rv)['ok200']}, spool {cell(6, rv)['spool']}",
        ),
        (
            f"host {ch} scans a different cert dir from cycle {at}",
            good(range(at, nc + 1), [ch])
            and bool(cell(at, ch)["drift"])
            and cell(at, ch)["drift"][-1] > 0
            and other_drift == 0,
            "drift > 0 in the ingest response and as fleet.drift rows in the stored scan; 0 the next cycle; 0 for "
            "every other host in every cycle",
            "Each finding that appeared or vanished becomes one `fleet.drift` finding (severity info) in the new scan. "
            "The ingest response reports the number of changes as `drift`.",
            "Drift between scans",
            f"host {ch} cycle {at}: drift {cell(at, ch)['drift']}, "
            f"drift rows in DB {cell(at, ch)['drift_rows_newest']}; "
            f"cycle {at + 1}: {cell(at + 1, ch)['drift']}; drift rows from all other hosts and cycles: {other_drift}",
        ),
        (
            f"replay host {rp}'s previous bundle after cycle {REPLAY['after']}",
            rep.get("status") == 200
            and rep.get("body", {}).get("duplicate") is True
            and rep.get("body", {}).get("stored_findings") == 0
            and rep.get("scans_before") == rep.get("scans_after"),
            "200 with `duplicate: true`, 0 findings stored, no new scan",
            "a duplicate bundle prunes nothing",
            "Retention",
            f"status {rep.get('status')}, body {rep.get('body')}, scans for the host {rep.get('scans_before')} -> "
            f"{rep.get('scans_after')}",
        ),
        (
            "does a duplicate resend spend an ingest token?",
            bool(dup.get("got_429")) and dup.get("duplicates_before_429", 99) <= 10,
            "spent like any post: duplicates answered 200 with `duplicate: true`, at most 10 in a row, then 429",
            "Every post spends a token before the bundle is read, a duplicate resend included: it is answered `200` "
            "with `duplicate: true`, and after 10 in a row the next one gets `429`.",
            "Security, Ingest limits",
            f"{dup.get('sequence')}: "
            + (
                f"429 after {dup.get('duplicates_before_429')} duplicates"
                if dup.get("got_429")
                else "never reached 429, so duplicates were free"
            ),
        ),
        (
            f"retention at --keep-scans-per-host {result['keep_scans_per_host']}",
            over("pruned") == sum(want_prune) and [tot(c, "pruned") for c in range(1, nc + 1)] == want_prune,
            f"scans pruned per cycle {want_prune}; no host above {result['keep_scans_per_host']} stored scans",
            "After each stored bundle the daemon deletes that host's scans beyond the newest N ... Change the number "
            "with `pqcscan daemon --keep-scans-per-host N`",
            "Retention",
            f"pruned per cycle {[tot(c, 'pruned') for c in range(1, nc + 1)]}; most scans on one host "
            f"{max(cell(nc, h)['scans'] for h in allh)}",
        ),
        (
            "429 and 503 answers",
            over("s429") == over("s503") == over("other") == 0,
            "no 429, no 503, no other ingest status in any cycle",
            "Each host may post a burst of 10 bundles, refilled at one per minute",
            "Security",
            f"429: {over('s429')}, 503: {over('s503')}, other: {over('other')}",
        ),
        (
            "rejected spool files",
            over("rejected") == 0,
            "0 files in spool/rejected on every host (nothing in this plan draws a 400, 403 or 413 on ingest)",
            "A spooled file that gets one of these moves to `<state dir>/spool/rejected/`",
            "Known limits",
            f"files over all cycles and hosts: {over('rejected')}",
        ),
        (
            "labels",
            all(c["labels_min_max"] == [N_LABELS, N_LABELS] for c in cyc),
            f"{N_LABELS} labels on every host, constant (the cap is 64)",
            "Labels merge across bundles. Host labels are capped at 64 per host",
            "Security, Ingest limits",
            f"min and max labels per host, by cycle: {[tuple(c['labels_min_max']) for c in cyc]}",
        ),
        (
            "agent exit codes",
            over("rc") == 0,
            "every agent run exits 0 (reported or spooled)",
            "`--once` (one cycle; exit 1 if the scan crashed or the collector permanently rejected the report, a "
            "spooled report exits 0)",
            "Agent loop",
            f"exit codes summed over all runs: {over('rc')}",
        ),
        (
            "collector log",
            not result["collector_log_warnings"],
            "no WARNING or ERROR lines (a failed prune would log one)",
            "If the trim itself fails the ingest still succeeds and a warning is logged.",
            "Retention",
            f"{len(result['collector_log_warnings'])} warning lines, {result['collector_log_info_lines']} info lines",
        ),
    ]
    return [
        {"fault": f, "ok": bool(ok), "expected": e, "cite": q, "source": f"FLEET.md {s}", "observed": o}
        for f, ok, e, q, s, o in rows
    ]


# --- observe: the real soak ------------------------------------------------------------------------------------
_ACCESS = re.compile(r'"POST (/api/ingest|/api/agents/enroll) HTTP/[\d.]+" (\d{3})')


def _readonly_engine(target: str):
    """Engine on the live collector DB that cannot write: SQLite `mode=ro`, Postgres read-only transactions."""
    from sqlalchemy import create_engine

    if "://" in target:
        return create_engine(target, connect_args={"options": "-c default_transaction_read_only=on"})
    return create_engine(f"sqlite:///file:{Path(target).resolve()}?mode=ro&uri=true")


def observe(*, target: str, access_log: Path | None, cycles: int, interval: float, command: str = "") -> dict[str, Any]:
    """REAL soak, collector side: every `interval` seconds snapshot a running collector's DB and access log.

    No agents are started here; the real hosts run the shipped recipes. Records per cycle, per host: scans stored,
    labels, new scans since the last snapshot, old scans gone (retention), drift rows on the newest scan; and the
    ingest and enrol status counts from the uvicorn access log. Spool and exit codes are read on the hosts
    (soak-real.md)."""
    from sqlalchemy import text

    probe = SimpleNamespace(engine=_readonly_engine(target))     # never Repo(): its constructor path can migrate
    offset = 0
    mark = None            # highest scan id seen at the previous snapshot
    prev: dict[str, int] = {}
    out: dict[str, Any] = {"SIMULATED": False, "mode": "observe", "command": command, "interval_s": interval,
                           "started_at": dt.datetime.now(dt.UTC).isoformat(), "commit": _git("rev-parse", "HEAD"),
                           "cycles": []}
    for c in range(1, cycles + 1):
        t0 = time.monotonic()
        st = _db_state(probe, 0)
        with probe.engine.connect() as con:
            top = con.execute(text("select coalesce(max(id), 0) from scans")).scalar()
            new = dict(con.execute(text("select h.machine_id, count(s.id) from hosts h left join scans s "
                                        "on s.host_id = h.id and s.id > :m group by h.machine_id"),
                                   {"m": mark or 0}).all()) if mark is not None else {}
            last = dict(con.execute(text("select machine_id, last_seen from hosts")).all())
        statuses: dict[str, dict[str, int]] = {"ingest": {}, "enroll": {}}
        if access_log and access_log.exists():
            with access_log.open("rb") as fh:
                fh.seek(offset)
                for line in fh.read().decode(errors="replace").splitlines():
                    if m := _ACCESS.search(line):
                        k = "ingest" if m.group(1).endswith("ingest") else "enroll"
                        statuses[k][m.group(2)] = statuses[k].get(m.group(2), 0) + 1
                offset = fh.tell()
        hosts = {m: {**d, "new_scans": new.get(m), "old_scans_gone": (max(0, prev[m] - (d["scans"] - new.get(m, 0)))
                                                                         if m in prev and mark is not None else None),
                     "last_seen": str(last.get(m))} for m, d in st.items()}
        out["cycles"].append({"cycle": c, "at": dt.datetime.now(dt.UTC).isoformat(), "hosts": hosts,
                              "hosts_enrolled": len(hosts), "statuses": statuses,
                              "scans_total": sum(d["scans"] for d in st.values()),
                              "drift_rows_total": sum(d["drift_rows_newest"] for d in st.values()),
                              "old_scans_gone_total": sum(h["old_scans_gone"] or 0 for h in hosts.values()),
                              "labels_min_max": [min((d["labels"] for d in st.values()), default=0),
                                                 max((d["labels"] for d in st.values()), default=0)]})
        mark, prev = top, {m: d["scans"] for m, d in st.items()}
        print(f"cycle {c}: {len(hosts)} hosts, {out['cycles'][-1]['scans_total']} scans, drift rows "
              f"{out['cycles'][-1]['drift_rows_total']}, old scans gone {out['cycles'][-1]['old_scans_gone_total']}, "
              f"ingest {statuses['ingest']}, enrol {statuses['enroll']}", flush=True)
        if c < cycles:
            time.sleep(max(0.0, interval - (time.monotonic() - t0)))
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / f"soak-real-{dt.datetime.now(dt.UTC):%Y%m%d}.json"
    n = 1
    while path.exists():
        n += 1
        path = RESULTS / f"soak-real-{dt.datetime.now(dt.UTC):%Y%m%d}-{n}.json"
    path.write_text(json.dumps(out, indent=2) + "\n")
    out["result_file"] = path.name
    return out


# --- markdown ---------------------------------------------------------------------------------------------------
def render(result: dict) -> str:
    esc = lambda s: str(s).replace("|", "\\|")  # noqa: E731
    lines = [
        f"#### {result['db']} ({result['started_at'][:19]}Z, commit {result['commit'][:9]}"
        f"{'+uncommitted' if result['tree_dirty'] else ''})",
        "",
        "| fault | expected | FLEET.md sentence | observed | match |",
        "|---|---|---|---|---|",
    ]
    for c in result["checks"]:
        lines.append(
            f"| {esc(c['fault'])} | {esc(c['expected'])} | {esc(c['cite'])} ({c['source']}) | "
            f"{esc(c['observed'])} | {'yes' if c['ok'] else '**NO**'} |"
        )
    lines += [
        "",
        "| cycle | wall s | load | reported/spooled/other | stored (200) | dup | 401 | 429 | 503 | enrol 201/403 | "
        "spool total (max) | rejected | drift rows | pruned | scans stored | labels min-max | agent s p50/max "
        "| ingest ms p50/p95 |",
        "|" + "---|" * 18,
    ]
    for cy in result["cycles"]:
        t, o = cy["totals"], cy["outcomes"]
        mx = max(v["spool"] for v in cy["cells"].values())
        lines.append(
            f"| {cy['cycle']}{' (collector down)' if cy['collector_down'] else ''} | {cy['duration_s']} | "
            f"{cy['loadavg_1m_at_start']} | {o['reported']}/{o['spooled']}/{o['rejected'] + o['crash']} | "
            f"{t['ok200']} | {t['dup']} | {t['s401']} | {t['s429']} | {t['s503']} | "
            f"{t['enroll201']}/{t['enroll403']} | {t['spool']} ({mx}) | {t['rejected']} | "
            f"{cy['drift_rows_total']} | {t['pruned']} | {t['scans']} | {cy['labels_min_max'][0]}-"
            f"{cy['labels_min_max'][1]} | {cy['agent_secs_p50_max'][0]}/{cy['agent_secs_p50_max'][1]} | "
            f"{cy['ingest_server_ms_p50_p95'][0]:.0f}/{cy['ingest_server_ms_p50_p95'][1]:.0f} |"
        )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", choices=("sqlite", "postgres"), default="sqlite")
    ap.add_argument("--hosts", type=int, default=30)
    ap.add_argument("--cycles", type=int, default=7)
    ap.add_argument("--interval", type=float, default=60.0, help="minimum seconds between cycle starts")
    ap.add_argument("--fault-plan", choices=("default", "none"), default="default")
    ap.add_argument("--workers", type=int, default=6, help="agent subprocesses running at once")
    ap.add_argument("--keep-scans-per-host", type=int, default=3)
    ap.add_argument("--observe", metavar="DB", help="REAL soak: snapshot this running collector's DB (path or URL)")
    ap.add_argument("--access-log", type=Path, help="with --observe: the collector's uvicorn log, for 429/503 counts")
    ap.add_argument("--render", nargs="+", metavar="JSON", help="print markdown tables for result files and exit")
    args = ap.parse_args()
    if args.render:
        print("\n\n".join(render(json.loads(Path(p).read_text())) for p in args.render))
        return 0
    if args.observe:                # REAL soak: read a running collector, never start the simulation
        r = observe(
            target=args.observe,
            access_log=args.access_log,
            cycles=args.cycles,
            interval=args.interval,
            command="python -m benchmark.fleet.soak " + shlex.join(sys.argv[1:]),
        )
        print("result:", r["result_file"])
        return 0
    r = run(
        db=args.db,
        hosts=args.hosts,
        cycles=args.cycles,
        interval=args.interval,
        faults=args.fault_plan == "default",
        workers=args.workers,
        keep=args.keep_scans_per_host,
        command="python -m benchmark.fleet.soak " + shlex.join(sys.argv[1:]),
    )
    print(render(r))
    print(f"\nanomalies: {len(r['anomalies'])}  result: {r.get('result_file')}")
    return 0 if all(c["ok"] for c in r["checks"]) else 1


if __name__ == "__main__":
    sys.exit(main())
