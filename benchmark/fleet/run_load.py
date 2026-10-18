"""Drive the fleet collector with simulated agent hosts (locust) and record the result.

    python -m benchmark.fleet.run_load --db sqlite|postgres --hosts 500 --spawn-rate 50 --duration 120s \
        --findings-per-bundle 1670

Writes benchmark/fleet/results/load-<db>-<YYYYMMDD>[-<hosts>h][-herd][-<tag>][-N].json and appends a row to LOAD.md
(not with --no-record). --profile DIR also records a profile there (see benchmark/fleet/profiles/README.md).
PASS means the ingest p95 is under 2 s. 429 and 503 are counted apart from errors.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

import httpx

from . import _bundles, _collector, _profile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
P95_LIMIT_MS = 2000
DEFAULT_FINDINGS = 1670          # a real scan stores about this many (FLEET-EVIDENCE F19)
JITTER_WINDOW_S = 7200           # FLEET.md: daily timer, 2 h random delay
LITTLE_BAND = (0.9, 1.1)
ROW_COLUMNS = 22                 # cells in a LOAD.md row; the header written by _load_md_head has the same count
SRC_DIRS = ("src/pqcscan/daemon", "src/pqcscan/store")      # the collector code a result depends on


def interval_for(*, hosts: int, rate: float) -> float:
    """Seconds between one host's posts so that `hosts` hosts offer `rate` posts/s in total."""
    if rate <= 0:
        raise ValueError("rate must be > 0")
    return hosts / rate


def littles(*, hosts: int, interval_s: float, mean_ms: float, achieved_rps: float,
            duration_s: float | None = None) -> dict:
    """Little's law for the closed loop locust runs: each host cycles every (interval + mean response), so
    N hosts offer N / (interval + W) requests per second. A measured rate outside LITTLE_BAND of that means
    requests were lost (timeouts, crashed users) or the clock lied: the run is a measurement defect.
    A run shorter than two intervals is not in steady state: `measurement_defect` is None (not evaluated).
    Pass the unrounded achieved rate; the result rounds for display only."""
    expected = hosts / (interval_s + mean_ms / 1000.0)
    ratio = achieved_rps / expected if expected else 0.0
    ok = LITTLE_BAND[0] <= ratio <= LITTLE_BAND[1]
    short = duration_s is not None and duration_s < 2 * interval_s
    return {
        "offered_rps": round(hosts / interval_s, 4), "mean_ms": mean_ms,
        "littles_expected_rps": round(expected, 4), "littles_ratio": round(ratio, 3),
        "measurement_defect": None if short else not ok,
        "measurement_defect_reason": "run shorter than two intervals; Little's law not evaluated" if short else
        "" if ok else
        f"achieved {achieved_rps:.2f} rps is {ratio:.2f} of the Little's law expectation {expected:.2f} rps "
        f"({hosts} hosts / ({interval_s:g} s + {mean_ms / 1000:.2f} s)); requests were lost or timed out",
    }


def _box() -> dict:
    cpu = next((ln.split(":", 1)[1].strip() for ln in Path("/proc/cpuinfo").read_text().splitlines()
                if ln.startswith("model name")), "unknown")
    mem_kb = int(Path("/proc/meminfo").read_text().split()[1])
    return {"cpus": os.cpu_count(), "cpu_model": cpu, "mem_gb": round(mem_kb / 1024 / 1024)}


def _load_md_head() -> str:
    b = _box()
    return (
        f"Box: {b['cpus']} cores ({b['cpu_model']}), {b['mem_gb']} GB, local loopback; locust and the collector share "
        "one host, so these numbers are not a network result.\n\n"
        "Locust drives simulated agent hosts at the collector (uvicorn plus the database, same host). Pass means "
        "ingest p95 under 2 s. Arrival is `staggered` (each host enrols and sends its first bundle at a random offset "
        "in the first interval, so the offered load is steady at hosts/interval posts/s) or `herd` (every host enrols "
        "and posts as it spawns: a 10 s ramp at 50 hosts/s for 500 hosts). Read the rate, not the host count: "
        "FLEET.md's daily timer with a 2 h random delay puts 2,000 hosts at 0.28 posts/s, while 500 hosts every 60 s "
        "is 8.3 posts/s, about 60,000 daily hosts. `Little ratio` is the achieved rate over the Little's law "
        "expectation hosts / (interval + mean response); outside 0.9 to 1.1 the run lost requests and is a "
        "measurement defect, not a capacity result (None: run shorter than two intervals, not evaluated). "
        "`parse slots` is how many bundles the collector parsed and stored at once. Rows from "
        "PR #92 (19-column format, 300-finding bundles) are in [LOAD-pr92.md](LOAD-pr92.md). The box was shared "
        "with unrelated work, so the load average "
        "column matters when reading a row. Postgres rows ran against a local `postgres:16-alpine` container.\n\n"
        "| date (UTC) | db | arrival | hosts | spawn/s | duration | findings/bundle | parse slots | ingest reqs "
        "| p50 ms | p95 ms "
        "| p99 ms | rps | offered rps | Little ratio | 429 | 503 | errors | p95 < 2 s "
        "| box load (1 min avg, start / end) | commit | command |\n"
        "|" + "---|" * ROW_COLUMNS + "\n")


def parse_duration(s: str) -> int:
    s = s.strip().lower()
    return int(s[:-1]) * {"s": 1, "m": 60}[s[-1]] if s[-1] in "sm" else int(s)


def _load() -> dict:
    """1-minute load average and CPU pressure (% of the last 60 s a task waited for a CPU); this box is shared."""
    try:
        psi = float(Path("/proc/pressure/cpu").read_text().splitlines()[0].split()[2].split("=")[1])
    except (OSError, IndexError, ValueError):
        psi = None
    return {"loadavg_1m": round(os.getloadavg()[0], 1), "cpu_pressure_avg60_pct": psi}


def _git(*args: str, strip: bool = True) -> str:
    out = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True).stdout
    return out.strip() if strip else out


def _src_hash(dirs: tuple[str, ...] = SRC_DIRS) -> str:
    """sha256 over the sources under `dirs` (default: the collector, daemon and store), names and contents, in order."""
    h = hashlib.sha256()
    for d in dirs:
        for f in sorted((REPO / d).rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                h.update(f.relative_to(REPO).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def _dirty_files() -> list[str]:
    """Paths `git status` reports, untracked included, minus this harness's own outputs (results/, profiles/ and
    LOAD.md). Other work in a shared checkout shows up here."""
    own = ("benchmark/fleet/results/", "benchmark/fleet/profiles/", "benchmark/fleet/LOAD.md")
    return [ln[3:] for ln in _git("status", "--porcelain", "--untracked-files=all", strip=False).splitlines()
            if not ln[3:].startswith(own)]


def _stored(url: str) -> tuple[int, int]:
    """(hosts, scans) the collector reports after the run, through its public API."""
    with httpx.Client(timeout=120) as c:
        ids = [h["host_id"] for h in c.get(f"{url}/api/fleet").json()]
        with ThreadPoolExecutor(16) as ex:
            n = sum(ex.map(lambda i: len(c.get(f"{url}/api/fleet/{i}").json()["scans"]), ids))
    return len(ids), n


def _stats(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as fh:
        return {row["Name"]: row for row in csv.DictReader(fh)}


def run(*, db: str, hosts: int, spawn_rate: int, duration_s: int, findings: int = DEFAULT_FINDINGS,
        interval_s: float | None = None, rate: float | None = None, stagger: bool = True, seed: int = 1,
        tag: str = "", results_dir: Path | None = None, record: bool = True, command: str = "",
        profile_dir: Path | None = None, md_path: Path | None = None, ingest_parallelism: int | None = None) -> dict:
    """One load run; returns the result dict (also written to `results_dir` and LOAD.md when `record`).
    `rate` (total posts/s offered by all hosts) sets the interval; else `interval_s`, default 60 s.
    `profile_dir` records a py-spy profile, slow callbacks and statement counts there and writes its summary.
    `md_path` overrides the LOAD.md the row is appended to. `ingest_parallelism` overrides the collector's per-dialect
    default; the result records the value the collector resolved."""
    interval_s = interval_for(hosts=hosts, rate=rate) if rate is not None else interval_s or 60.0
    if record:                                    # fail before a long run, not after it
        _check_md_columns(md_path or HERE / "LOAD.md", ROW_COLUMNS)
    started = datetime.now(UTC)
    load_start = _load()
    with tempfile.TemporaryDirectory(prefix="fleet-load-") as td:
        work = Path(td)
        template = work / "template.json"
        template.write_text(json.dumps(_bundles.build_template(work, findings)))
        prefix = work / "run"
        counters = work / "counters.json"
        requests_csv = work / "requests.csv"
        locust_cmd = [sys.executable, "-m", "locust", "-f", str(HERE / "locustfile.py"), "--headless",
                      "-u", str(hosts), "-r", str(spawn_rate), "-t", f"{duration_s}s", "--stop-timeout", "70",
                      "--csv", str(prefix), "--csv-full-history", "--only-summary"]
        info: dict = {}
        with _collector.collector(db, work, profile_dir=profile_dir, ingest_parallelism=ingest_parallelism,
                                  info=info) as url:
            env = {**os.environ, "LOAD_TEMPLATE": str(template), "LOAD_ENROLL_TOKEN": _collector.ENROLL_TOKEN,
                   "LOAD_INTERVAL_S": str(interval_s), "LOAD_COUNTERS": str(counters), "LOAD_PREFIX": "m-load-",
                   "LOAD_STAGGER": "1" if stagger else "0", "LOAD_SEED": str(seed),
                   "LOAD_REQUESTS_CSV": str(requests_csv)}
            locust_cmd += ["--host", url]
            t0 = time.monotonic()
            with _profile.pyspy(os.getpid(), profile_dir) if profile_dir else nullcontext():
                p = subprocess.run(locust_cmd, env=env, capture_output=True, text=True)
            wall_s = round(time.monotonic() - t0, 1)
            stored_hosts, stored_scans = _stored(url) if p.returncode in (0, 1) else (0, 0)
        if p.returncode not in (0, 1) or not (work / "run_stats.csv").exists():   # 1 = locust saw failures
            raise RuntimeError(f"locust failed ({p.returncode}):\n{p.stderr[-2000:]}")
        stats = _stats(work / "run_stats.csv")
        ing, enr, agg = (stats.get(k, {}) for k in ("ingest", "enroll", "Aggregated"))
        if not counters.exists():
            raise RuntimeError("locust wrote no counters file; its 429/503 counts would be unknown")
        seen = json.loads(counters.read_text())
        failures = list(csv.DictReader((work / "run_failures.csv").open(newline="")))
        raw_csvs = {"requests": requests_csv.read_bytes() if requests_csv.exists() else b"",
                    "history": (work / "run_stats_history.csv").read_bytes()}
    p95 = float(ing.get("95%", 0) or 0)

    def error_rate(row: dict) -> float:
        return round(int(row.get("Failure Count", 0) or 0) / max(int(row.get("Request Count", 0) or 0), 1), 4)

    dirty = _dirty_files()
    achieved = float(ing.get("Requests/s", 0) or 0)
    mean_ms = float(ing.get("Average Response Time", 0) or 0)
    result = {
        "db": db, "hosts": hosts, "spawn_rate": spawn_rate, "duration_s": duration_s, "interval_s": interval_s,
        "findings_per_bundle": findings, "arrival": "staggered" if stagger else "herd",
        "requests": int(ing.get("Request Count", 0) or 0),
        "p50_ms": float(ing.get("50%", 0) or 0), "p95_ms": p95, "p99_ms": float(ing.get("99%", 0) or 0),
        "rps": round(achieved, 2),
        **littles(hosts=hosts, interval_s=interval_s, mean_ms=mean_ms, achieved_rps=achieved, duration_s=duration_s),
        "hosts_daily_2h_equiv": round(hosts / interval_s * JITTER_WINDOW_S),
        "hosts_daily_24h_equiv": round(hosts / interval_s * 86400), "schema_version": 2,
        "requests_csv": None, "history_csv": None,
        "http_429": seen.get("http_429", 0), "http_503": seen.get("http_503", 0),
        "errors": int(agg.get("Failure Count", 0) or 0),
        "ingest_error_rate": error_rate(ing), "enroll_error_rate": error_rate(enr),
        "enroll_503": seen.get("enroll_503", 0),
        "stored_hosts": stored_hosts, "stored_scans": stored_scans, "seed": seed,
        "ingest_parallelism": info["ingest_parallelism"],
        "enroll_requests": int(enr.get("Request Count", 0) or 0), "enroll_p95_ms": float(enr.get("95%", 0) or 0),
        "failure_samples": [f"{f['Name']}: {f['Error']} x{f['Occurrences']}" for f in failures[:10]],
        "pass_p95_lt_2s": p95 < P95_LIMIT_MS and bool(ing),
        "commit": _git("rev-parse", "HEAD"), "src_hash": _src_hash(), "tree_dirty": bool(dirty), "dirty_files": dirty,
        "box": _box(),
        "box_load_start": load_start, "box_load_end": _load(),
        "command": command, "locust_command": shlex.join(locust_cmd), "started_at": started.isoformat(),
    }
    if profile_dir:
        _profile.summarise(profile_dir, ingest_requests=result["requests"], enroll_requests=result["enroll_requests"],
                           wall_s=wall_s, run=result)
        pd = profile_dir.resolve()
        result["profile_dir"] = str(pd.relative_to(REPO)) if pd.is_relative_to(REPO) else str(pd)
    if record:
        out = results_dir or HERE / "results"
        out.mkdir(parents=True, exist_ok=True)
        base = (f"load-{db}-{started:%Y%m%d}" + (f"-{hosts}h" if hosts != 500 else "")
                + (f"-r{rate:g}" if rate is not None else "") + ("" if stagger else "-herd")
                + (f"-{tag}" if tag else ""))
        path, n = out / f"{base}.json", 1
        while path.exists():                  # never overwrite an earlier run's record
            n += 1
            path = out / f"{base}-{n}.json"
        for key, suffix in (("requests", "requests"), ("history", "history")):
            gz = out / f"{path.stem}-{suffix}.csv.gz"
            gz.write_bytes(gzip.compress(raw_csvs[key]))
            result[f"{key}_csv"] = gz.name
        path.write_text(json.dumps(result, indent=2) + "\n")
        result["result_file"] = path.name
        _append_row(result, started, md_path)
    return result


def _check_md_columns(md: Path, ncols: int) -> None:
    """Refuse to append a row under a header with a different column count: the cells would shift silently."""
    if not md.exists():
        return
    header = next((ln for ln in md.read_text().splitlines() if ln.startswith("| date")), "")
    if header.count("|") - 1 != ncols:
        raise RuntimeError(f"{md} has a {header.count('|') - 1}-column header but a row has {ncols} cells; "
                           "move the old table aside (as LOAD-pr92.md was) and let the harness start a new one")


def _append_row(r: dict, started: datetime, md: Path | None = None) -> None:
    md = md or HERE / "LOAD.md"
    if not md.exists():
        md.write_text(_load_md_head())
    commit = r["commit"][:9] + ("+dirty tree" if r["tree_dirty"] else "")
    cells = [f"{started:%Y-%m-%d %H:%M}", r["db"], r["arrival"], r["hosts"], r["spawn_rate"], f"{r['duration_s']} s",
             r["findings_per_bundle"], r["ingest_parallelism"], r["requests"], f"{r['p50_ms']:.0f}",
             f"{r['p95_ms']:.0f}", f"{r['p99_ms']:.0f}",
             r["rps"], r["offered_rps"], r["littles_ratio"], r["http_429"], r["http_503"], r["errors"],
             "PASS" if r["pass_p95_lt_2s"] else "FAIL",
             f"{r['box_load_start']['loadavg_1m']} / {r['box_load_end']['loadavg_1m']}", commit, f"`{r['command']}`"]
    _check_md_columns(md, len(cells))
    row = "| " + " | ".join(map(str, cells)) + " |\n"
    with md.open("a") as fh:
        fh.write(row)


def _at_least_one(s: str) -> int:
    n = int(s)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, not {n}")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", choices=("sqlite", "postgres"), required=True)
    ap.add_argument("--hosts", type=int, default=500)
    ap.add_argument("--spawn-rate", type=int, default=50)
    ap.add_argument("--duration", default="120s", help="e.g. 120s, 2m")
    ap.add_argument("--findings-per-bundle", type=int, default=DEFAULT_FINDINGS)
    ap.add_argument("--herd", action="store_true", help="post as soon as spawned (default: random offset)")
    ap.add_argument("--seed", type=int, default=1, help="seeds the per-host start offsets; recorded in the JSON")
    ap.add_argument("--tag", default="", help="suffix for the result file name, e.g. a code revision label")
    ap.add_argument("--profile", type=Path, default=None, metavar="DIR",
                    help="record py-spy, asyncio slow callbacks and statements per ingest into DIR")
    ap.add_argument("--ingest-parallelism", type=_at_least_one, default=None, metavar="N",
                    help="bundles the collector parses/stores at once (default: 2 on SQLite, 4 on Postgres)")
    ap.add_argument("--no-record", action="store_true", help="write no result file and no LOAD.md row (dry runs)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--interval", type=float, default=None, help="seconds between bundles from one host (default 60)")
    g.add_argument("--rate", type=float, default=None, help="total posts/s all hosts offer; sets the interval")
    args = ap.parse_args()
    cmd = "python -m benchmark.fleet.run_load " + shlex.join(sys.argv[1:])
    r = run(db=args.db, hosts=args.hosts, spawn_rate=args.spawn_rate, duration_s=parse_duration(args.duration),
            findings=args.findings_per_bundle, interval_s=args.interval, rate=args.rate, stagger=not args.herd,
            seed=args.seed, tag=args.tag, command=cmd, record=not args.no_record, profile_dir=args.profile,
            ingest_parallelism=args.ingest_parallelism)
    print(json.dumps({k: v for k, v in r.items() if k not in ("command", "locust_command")}, indent=2))
    return 0 if r["pass_p95_lt_2s"] and not r["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
