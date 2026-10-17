"""Drive the fleet collector with simulated agent hosts (locust) and record the result.

    python -m benchmark.fleet.run_load --db sqlite|postgres --hosts 500 --spawn-rate 50 --duration 120s \
        --findings-per-bundle 300

Writes benchmark/fleet/results/load-<db>-<YYYYMMDD>[-<hosts>h][-herd][-N].json and appends a row to LOAD.md.
PASS means the ingest p95 is under 2 s. 429 and 503 are counted apart from errors.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import _bundles, _collector

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
P95_LIMIT_MS = 2000
LOAD_MD_HEAD = (
    "Box: 8 cores, 31 GB, local loopback; locust and the collector share one host, so these numbers are not a network "
    "result.\n\n"
    "Locust drives simulated agent hosts at the collector (uvicorn plus the database, same host). Pass means ingest "
    "p95 under 2 s. Arrival is `staggered` (each host's first bundle at a random offset in the first minute, steady "
    "hosts/60 s) or `herd` (every host posts as it spawns). The box was shared with unrelated work, so the load "
    "average column matters when reading a row. Postgres rows ran against a local `postgres:16-alpine` container.\n\n"
    "| date (UTC) | db | arrival | hosts | spawn/s | duration | findings/bundle | ingest reqs | p50 ms | p95 ms "
    "| p99 ms | rps | 429 | 503 | errors | p95 < 2 s | box load (1 min avg, start / end) | commit | command |\n"
    "|" + "---|" * 19 + "\n")


def parse_duration(s: str) -> int:
    s = s.strip().lower()
    return int(s[:-1]) * {"s": 1, "m": 60}[s[-1]] if s[-1] in "sm" else int(s)


def _load() -> dict:
    """1-minute load average and CPU pressure (% of the last 60 s a task waited for a CPU); this box is shared."""
    try:
        psi = float(Path("/proc/pressure/cpu").read_text().split()[1].split("avg60=")[1])
    except (OSError, IndexError, ValueError):
        psi = None
    return {"loadavg_1m": round(os.getloadavg()[0], 1), "cpu_pressure_avg60_pct": psi}


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True).stdout.strip()


def _stats(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as fh:
        return {row["Name"]: row for row in csv.DictReader(fh)}


def run(*, db: str, hosts: int, spawn_rate: int, duration_s: int, findings: int, interval_s: float = 60.0,
        stagger: bool = True, results_dir: Path | None = None, record: bool = True, command: str = "") -> dict:
    """One load run; returns the result dict (also written to `results_dir` and LOAD.md when `record`)."""
    started = datetime.now(UTC)
    load_start = _load()
    with tempfile.TemporaryDirectory(prefix="fleet-load-") as td:
        work = Path(td)
        template = work / "template.json"
        template.write_text(json.dumps(_bundles.build_template(work, findings)))
        prefix = work / "run"
        counters = work / "counters.json"
        locust_cmd = [sys.executable, "-m", "locust", "-f", str(HERE / "locustfile.py"), "--headless",
                      "-u", str(hosts), "-r", str(spawn_rate), "-t", f"{duration_s}s", "--stop-timeout", "70",
                      "--csv", str(prefix), "--only-summary"]
        with _collector.collector(db, work) as url:
            env = {**os.environ, "LOAD_TEMPLATE": str(template), "LOAD_ENROLL_TOKEN": _collector.ENROLL_TOKEN,
                   "LOAD_INTERVAL_S": str(interval_s), "LOAD_COUNTERS": str(counters), "LOAD_PREFIX": "m-load-",
                   "LOAD_STAGGER": "1" if stagger else "0"}
            locust_cmd += ["--host", url]
            p = subprocess.run(locust_cmd, env=env, capture_output=True, text=True)
        if p.returncode not in (0, 1) or not (work / "run_stats.csv").exists():   # 1 = locust saw failures
            raise RuntimeError(f"locust failed ({p.returncode}):\n{p.stderr[-2000:]}")
        stats = _stats(work / "run_stats.csv")
        ing, enr, agg = (stats.get(k, {}) for k in ("ingest", "enroll", "Aggregated"))
        seen = json.loads(counters.read_text()) if counters.exists() else {}
        failures = list(csv.DictReader((work / "run_failures.csv").open(newline="")))
    p95 = float(ing.get("95%", 0) or 0)
    result = {
        "db": db, "hosts": hosts, "spawn_rate": spawn_rate, "duration_s": duration_s, "interval_s": interval_s,
        "findings_per_bundle": findings, "arrival": "staggered" if stagger else "herd",
        "requests": int(ing.get("Request Count", 0) or 0),
        "p50_ms": float(ing.get("50%", 0) or 0), "p95_ms": p95, "p99_ms": float(ing.get("99%", 0) or 0),
        "rps": round(float(ing.get("Requests/s", 0) or 0), 2),
        "http_429": seen.get("http_429", 0), "http_503": seen.get("http_503", 0),
        "errors": int(agg.get("Failure Count", 0) or 0),
        "enroll_requests": int(enr.get("Request Count", 0) or 0), "enroll_p95_ms": float(enr.get("95%", 0) or 0),
        "failure_samples": [f"{f['Name']}: {f['Error']} x{f['Occurrences']}" for f in failures[:10]],
        "pass_p95_lt_2s": p95 < P95_LIMIT_MS and bool(ing),
        "commit": _git("rev-parse", "HEAD"), "tree_dirty": bool(_git("status", "--porcelain", "--untracked-files=no")),
        "box_load_start": load_start, "box_load_end": _load(),
        "command": command, "locust_command": shlex.join(locust_cmd), "started_at": started.isoformat(),
    }
    if record:
        out = results_dir or HERE / "results"
        out.mkdir(parents=True, exist_ok=True)
        base = f"load-{db}-{started:%Y%m%d}" + (f"-{hosts}h" if hosts != 500 else "") + ("" if stagger else "-herd")
        path, n = out / f"{base}.json", 1
        while path.exists():                  # never overwrite an earlier run's record
            n += 1
            path = out / f"{base}-{n}.json"
        path.write_text(json.dumps(result, indent=2) + "\n")
        result["result_file"] = path.name
        _append_row(result, started)
    return result


def _append_row(r: dict, started: datetime) -> None:
    md = HERE / "LOAD.md"
    if not md.exists():
        md.write_text(LOAD_MD_HEAD)
    commit = r["commit"][:9] + ("+uncommitted" if r["tree_dirty"] else "")
    cells = [f"{started:%Y-%m-%d %H:%M}", r["db"], r["arrival"], r["hosts"], r["spawn_rate"], f"{r['duration_s']} s",
             r["findings_per_bundle"], r["requests"], f"{r['p50_ms']:.0f}", f"{r['p95_ms']:.0f}", f"{r['p99_ms']:.0f}",
             r["rps"], r["http_429"], r["http_503"], r["errors"], "PASS" if r["pass_p95_lt_2s"] else "FAIL",
             f"{r['box_load_start']['loadavg_1m']} / {r['box_load_end']['loadavg_1m']}", commit, f"`{r['command']}`"]
    row = "| " + " | ".join(map(str, cells)) + " |\n"
    with md.open("a") as fh:
        fh.write(row)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", choices=("sqlite", "postgres"), required=True)
    ap.add_argument("--hosts", type=int, default=500)
    ap.add_argument("--spawn-rate", type=int, default=50)
    ap.add_argument("--duration", default="120s", help="e.g. 120s, 2m")
    ap.add_argument("--findings-per-bundle", type=int, default=300)
    ap.add_argument("--herd", action="store_true", help="post as soon as spawned (default: random offset)")
    ap.add_argument("--interval", type=float, default=60.0, help="seconds between bundles from one host")
    args = ap.parse_args()
    cmd = "python -m benchmark.fleet.run_load " + shlex.join(sys.argv[1:])
    r = run(db=args.db, hosts=args.hosts, spawn_rate=args.spawn_rate, duration_s=parse_duration(args.duration),
            findings=args.findings_per_bundle, interval_s=args.interval, stagger=not args.herd, command=cmd)
    print(json.dumps({k: v for k, v in r.items() if k not in ("command", "locust_command")}, indent=2))
    return 0 if r["pass_p95_lt_2s"] and not r["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
