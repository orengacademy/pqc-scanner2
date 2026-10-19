# Fleet Capacity and Real-Soak Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Explain and fix (or restate) the PR #92 load failure with profiles, measure collector capacity under FLEET.md's own arrival model on a rented box, give the collector a defined overload behaviour, launch a real five-host soak, measure test strength with mutation and coverage-guided fuzzing, resolve the two Contradicted claims, and regrade the evidence page.

**Architecture:** The existing locust harness (`benchmark/fleet/run_load.py`, `locustfile.py`, `_collector.py`, `_bundles.py`) gains a rate-based arrival, Little's law fields, per-request CSV and a `--profile` mode (py-spy, asyncio slow-callback log, SQLite trace callback, `pg_stat_statements` + `auto_explain`). Cloud scripts under `benchmark/fleet/cloud/` create a DigitalOcean load box and the soak fleet (collector + 3 Linux agents), and a scheduled GitHub workflow runs the Windows agents. Product changes are confined to what the profile names, a bounded ingest queue in `daemon/fleet.py`, and the Windows installer fix.

**Tech Stack:** Python 3.11, locust 2.46, py-spy, SQLAlchemy 2, psycopg 3, postgres:16-alpine (Docker), mutmut 3, atheris, coverage.py, doctl (DigitalOcean), cloud-init, systemd, GitHub Actions (`windows-2022`, `windows-latest`), Pester 5.

**Spec:** `docs/superpowers/specs/2026-10-18-fleet-capacity-spec.md`

## Global Constraints

- No new product features. Product changes allowed: performance fixes the profile names, the bounded ingest queue (item 3), the installer fix (item 6). Everything else under `benchmark/`, `tests/`, `docs/`, `.github/`, `packaging/fleet/`.
- Python >= 3.11; line length 120; `ruff check` and `mypy src` clean; benchmark scripts ruff-clean.
- Every result file carries the command, the commit, `src_hash` over tracked and untracked collector sources, the box spec, and the seed.
- Nothing committed or recorded contains a token, a password or a private key. Recorded commands pass through the existing redaction (`soak.py::_redact_arg`) or carry placeholders.
- Project Python is `.venv/bin/python`; install with `uv pip install -e ".[dev,verify]"` (no `pip` in the venv).
- Tests: `.venv/bin/python -m pytest -q -p no:cacheprovider <paths>`; never run the full suite while a load or fuzz run is active on this box.
- Commit trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Branch `verify/fleet-capacity` from `77867a1`. The baseline commit for ratios and before/after is `77867a1`.

---

### Task 1: Rate-based arrival, Little's law, per-request CSV, real-size bundles

**Files:**
- Modify: `benchmark/fleet/run_load.py`
- Modify: `benchmark/fleet/locustfile.py`
- Modify: `benchmark/fleet/LOAD.md` (header only, via `_load_md_head`)
- Test: `tests/benchmark/test_fleet_load_smoke.py`, new `tests/benchmark/test_run_load_fields.py`

**Interfaces:**
- Consumes: `run_load.run(...)` as it exists (keyword-only), `locustfile` env contract (`LOAD_*`).
- Produces: `run_load.run(*, db, hosts, spawn_rate, duration_s, findings=1670, interval_s=None, rate=None, stagger=True, seed=1, tag="", results_dir=None, record=True, command="", profile_dir=None) -> dict` (profile_dir unused until Task 2); `run_load.littles(hosts, interval_s, mean_ms, achieved_rps) -> dict`; `run_load.interval_for(hosts, rate) -> float`; env `LOAD_REQUESTS_CSV`; result keys `offered_rps`, `mean_ms`, `littles_expected_rps`, `littles_ratio`, `measurement_defect`, `measurement_defect_reason`, `hosts_daily_2h_equiv`, `hosts_daily_24h_equiv`, `requests_csv`, `history_csv`, `schema_version: 2`.

- [ ] **Step 1: Failing test for `littles` and the new result keys**

```python
# tests/benchmark/test_run_load_fields.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import run_load


def test_littles_law_matches_closed_loop_expectation():
    # 120 hosts, 60 s think time, 500 ms mean response: expected 120 / 60.5 = 1.983 rps
    r = run_load.littles(hosts=120, interval_s=60.0, mean_ms=500.0, achieved_rps=1.98)
    assert abs(r["littles_expected_rps"] - 1.983) < 0.01
    assert 0.99 < r["littles_ratio"] < 1.01
    assert r["measurement_defect"] is False


def test_littles_law_flags_lost_requests():
    r = run_load.littles(hosts=500, interval_s=60.0, mean_ms=60000.0, achieved_rps=3.6)
    # 500 / 120 s = 4.17 expected; achieved 3.6 is 0.86: outside 0.9..1.1
    assert r["measurement_defect"] is True
    assert "0.86" in r["measurement_defect_reason"]


def test_rate_derives_interval():
    assert run_load.interval_for(hosts=500, rate=2.0) == 250.0
```

- [ ] **Step 2: Run, expect `AttributeError: module ... has no attribute 'littles'`**

Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/benchmark/test_run_load_fields.py`

- [ ] **Step 3: Implement in `run_load.py`**

Add after `P95_LIMIT_MS`:

```python
DEFAULT_FINDINGS = 1670          # a real scan stores about this many (FLEET-EVIDENCE F19)
JITTER_WINDOW_S = 7200           # FLEET.md: daily timer, 2 h random delay
LITTLE_BAND = (0.9, 1.1)


def interval_for(*, hosts: int, rate: float) -> float:
    """Seconds between one host's posts so that `hosts` hosts offer `rate` posts/s in total."""
    if rate <= 0:
        raise ValueError("rate must be > 0")
    return hosts / rate


def littles(*, hosts: int, interval_s: float, mean_ms: float, achieved_rps: float) -> dict:
    """Little's law for the closed loop locust runs: each host cycles every (interval + mean response), so
    N hosts offer N / (interval + W) requests per second. A measured rate outside LITTLE_BAND of that means
    requests were lost (timeouts, crashed users) or the clock lied: the run is a measurement defect."""
    expected = hosts / (interval_s + mean_ms / 1000.0)
    ratio = achieved_rps / expected if expected else 0.0
    ok = LITTLE_BAND[0] <= ratio <= LITTLE_BAND[1]
    return {
        "offered_rps": round(hosts / interval_s, 4), "mean_ms": mean_ms,
        "littles_expected_rps": round(expected, 4), "littles_ratio": round(ratio, 3),
        "measurement_defect": not ok,
        "measurement_defect_reason": "" if ok else
        f"achieved {achieved_rps:.2f} rps is {ratio:.2f} of the Little's law expectation {expected:.2f} rps "
        f"({hosts} hosts / ({interval_s:g} s + {mean_ms / 1000:.2f} s)); requests were lost or timed out",
    }
```

In `run(...)`: signature `findings: int = DEFAULT_FINDINGS, interval_s: float | None = None, rate: float | None = None`; resolve `if rate is not None: interval_s = interval_for(hosts=hosts, rate=rate)` else `interval_s = interval_s or 60.0`. After `stats` are parsed: `mean_ms = float(ing.get("Average Response Time", 0) or 0)` and merge `littles(hosts=hosts, interval_s=interval_s, mean_ms=mean_ms, achieved_rps=rps)` into `result`, plus `"hosts_daily_2h_equiv": round(hosts / interval_s * JITTER_WINDOW_S)`, `"hosts_daily_24h_equiv": round(hosts / interval_s * 86400)`, `"schema_version": 2`. Add `--csv-full-history` to `locust_cmd`; set `LOAD_REQUESTS_CSV` to `work / "requests.csv"`; when `record`, gzip-copy `requests.csv` to `<result stem>-requests.csv.gz` and `run_stats_history.csv` to `<result stem>-history.csv.gz`, and store their names in `requests_csv` / `history_csv`. Result file name: when `rate` is given append `-r{rate:g}` after the hosts part. CLI: `--rate` (float, posts/s, exclusive with `--interval` via `ap.add_mutually_exclusive_group()`), `--findings-per-bundle` default `DEFAULT_FINDINGS`. `_load_md_head()` gains two sentences: the arrival is `staggered` at `hosts/interval` posts/s (FLEET.md's daily timer with a 2 h jitter puts 2,000 hosts at 0.28 posts/s; 500 hosts every 60 s is 8.3 posts/s, about 60,000 daily hosts), and the Little's law column. Add columns `offered rps`, `Little ratio` to the row.

- [ ] **Step 4: Per-request CSV in `locustfile.py`**

```python
_REQ_CSV = os.environ.get("LOAD_REQUESTS_CSV")
_req_fh = open(_REQ_CSV, "w", newline="") if _REQ_CSV else None
if _req_fh:
    _req_fh.write("ts,name,status,response_ms,bytes\n")


@events.request.add_listener
def _record_request(request_type, name, response_time, response_length, response, exception, **_kw):
    if _req_fh:
        status = getattr(response, "status_code", 0) if response is not None else 0
        _req_fh.write(f"{time.time():.3f},{name},{status},{response_time:.1f},{response_length}\n")


@events.quitting.add_listener
def _close_requests(environment, **_kw):
    if _req_fh:
        _req_fh.close()
```

(`import time` at the top; the existing `_write_counters` listener stays.) Update the module docstring: `LOAD_REQUESTS_CSV`.

- [ ] **Step 5: Smoke test keeps passing, plus one assertion on the new keys**

In `test_five_hosts_ten_seconds_sqlite` add `assert r["schema_version"] == 2 and "littles_ratio" in r` and `assert r["findings_per_bundle"] == 50`. Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/benchmark/test_run_load_fields.py tests/benchmark/test_fleet_load_smoke.py`. Expected: all pass. Note: at 5 hosts for 10 s with a 60 s interval each host posts once; Little's law over a truncated run is not meaningful, so the smoke test does not assert `measurement_defect`.

- [ ] **Step 6: Ruff and commit**

Run: `.venv/bin/ruff check benchmark tests/benchmark`
Commit: `feat(bench): rate-based arrival, Little's law check, per-request CSV, 1,670-finding bundles by default`

---

### Task 2: Profile mode (py-spy, slow callbacks, statements per ingest)

**Files:**
- Create: `benchmark/fleet/_profile.py`
- Modify: `benchmark/fleet/_collector.py` (profile hooks: Postgres container flags, startup handler, trace callback)
- Modify: `benchmark/fleet/run_load.py` (`--profile DIR`)
- Create: `benchmark/fleet/profiles/README.md`
- Test: `tests/benchmark/test_profile_summary.py`

**Interfaces:**
- Consumes: `_collector.collector(db, workdir, enroll_token)`, `_collector.postgres_container()`, `run_load.run(..., profile_dir=...)`.
- Produces: `_profile.summarise(profile_dir: Path, *, ingest_requests: int, enroll_requests: int, wall_s: float, run: dict) -> dict` writing `summary.json` and `summary.md`; `_profile.pyspy(pid: int, out_dir: Path) -> ContextManager`; `_profile.top_frames(raw_path: Path, n: int = 10) -> list[dict]` (`{"frame", "self_pct", "total_pct"}`); `_collector.collector(..., profile_dir: Path | None = None)`; `_collector.postgres_container(profile: bool = False)` yields the same URL and, when profiling, keeps the container id in `_collector.LAST_PG_CONTAINER` for the log dump.

- [ ] **Step 1: Failing test for `top_frames` on a tiny collapsed-stack file**

```python
# tests/benchmark/test_profile_summary.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import _profile

RAW = """\
thread (123);run (uvicorn);_run_once (asyncio);ingest (fleet.py:150);load_bundle (bundle.py:140);loads (json) 60
thread (123);run (uvicorn);_run_once (asyncio);ingest (fleet.py:150);ingest_bundle (repo.py:470);execute 30
thread (123);run (uvicorn);_run_once (asyncio);_agent_host (fleet.py:95) 10
"""


def test_top_frames_shares_by_self_and_total(tmp_path):
    p = tmp_path / "pyspy.raw.txt"
    p.write_text(RAW)
    top = _profile.top_frames(p, n=3)
    by = {t["frame"]: t for t in top}
    assert by["loads (json)"]["self_pct"] == 60.0
    assert by["ingest (fleet.py:150)"]["total_pct"] == 90.0
    assert top[0]["frame"] == "loads (json)"       # ordered by self share
```

- [ ] **Step 2: Run, expect `ModuleNotFoundError`/`AttributeError`**

Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/benchmark/test_profile_summary.py`

- [ ] **Step 3: Write `_profile.py`**

```python
"""Profile one load run: py-spy samples of the harness process (the collector runs in it), asyncio slow callbacks,
and statements per ingest as the database driver or server counts them. Output lands in one directory:
pyspy.raw.txt (collapsed stacks), pyspy.speedscope.json (flame graph), asyncio-slow.log, statements.json,
auto_explain.log.gz (Postgres), summary.json, summary.md."""
from __future__ import annotations

import collections
import json
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def pyspy(pid: int, out_dir: Path, rate: int = 100) -> Iterator[None]:
    """Record `pid` (all threads, non-idle) until the block ends; raw + speedscope. Needs ptrace rights
    (root, or kernel.yama.ptrace_scope=0): fail loudly, never silently produce an empty profile."""
    if shutil.which("py-spy") is None:
        raise RuntimeError("py-spy is not installed (pip install py-spy)")
    out_dir.mkdir(parents=True, exist_ok=True)
    procs = [subprocess.Popen(["py-spy", "record", "-p", str(pid), "--rate", str(rate), "--threads", "--format", fmt,
                               "-o", str(out_dir / name)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
             for fmt, name in (("raw", "pyspy.raw.txt"), ("speedscope", "pyspy.speedscope.json"))]
    try:
        yield
    finally:
        for p in procs:
            p.send_signal(2)                       # SIGINT: py-spy flushes its output on interrupt
        for p in procs:
            _, err = p.communicate(timeout=60)
            if p.returncode not in (0, -2) or not (out_dir / "pyspy.raw.txt").exists():
                raise RuntimeError(f"py-spy failed ({p.returncode}): {err.decode()[-500:]}")


def top_frames(raw_path: Path, n: int = 10) -> list[dict]:
    """Self and total share per frame from py-spy's collapsed stacks (`frame;frame;... count`)."""
    self_c: collections.Counter[str] = collections.Counter()
    total_c: collections.Counter[str] = collections.Counter()
    samples = 0
    for line in raw_path.read_text().splitlines():
        stack, _, count = line.rpartition(" ")
        if not stack or not count.isdigit():
            continue
        c = int(count)
        samples += c
        frames = stack.split(";")
        self_c[frames[-1]] += c
        for f in set(frames):
            total_c[f] += c
    if not samples:
        return []
    rows = [{"frame": f, "self_pct": round(100 * self_c[f] / samples, 1), "total_pct": round(100 * total_c[f] / samples, 1)}
            for f in total_c]
    rows.sort(key=lambda r: (-r["self_pct"], -r["total_pct"], r["frame"]))
    return rows[:n]


def slow_callbacks(log_path: Path) -> dict:
    """asyncio's 'Executing <Handle ...> took N seconds' lines: count, max, top five."""
    rows = []
    if log_path.exists():
        for line in log_path.read_text().splitlines():
            if " took " in line and line.rstrip().endswith("seconds"):
                try:
                    rows.append((float(line.rsplit(" took ", 1)[1].split()[0]), line.strip()[:300]))
                except ValueError:
                    pass
    rows.sort(reverse=True)
    return {"count": len(rows), "max_s": rows[0][0] if rows else 0.0, "top": [r[1] for r in rows[:5]]}


def summarise(profile_dir: Path, *, ingest_requests: int, enroll_requests: int, wall_s: float, run: dict) -> dict:
    stmts = json.loads((profile_dir / "statements.json").read_text()) if (profile_dir / "statements.json").exists() else {}
    total = stmts.get("total_statements", 0)
    s = {
        "run": {k: run.get(k) for k in ("db", "hosts", "interval_s", "offered_rps", "rps", "p50_ms", "p95_ms",
                                         "findings_per_bundle", "commit", "src_hash", "box")},
        "wall_s": wall_s, "ingest_requests": ingest_requests, "enroll_requests": enroll_requests,
        "top_frames": top_frames(profile_dir / "pyspy.raw.txt", 10),
        "slow_callbacks": slow_callbacks(profile_dir / "asyncio-slow.log"),
        "statements_total": total,
        "statements_per_ingest": round(total / ingest_requests, 1) if ingest_requests else None,
        "statements_note": "total statements over the run divided by ingest requests; enrolments are included "
                           f"({enroll_requests} enrolls)",
        "statements_top": stmts.get("top", [])[:25],
    }
    (profile_dir / "summary.json").write_text(json.dumps(s, indent=2) + "\n")
    top3 = s["top_frames"][:3]
    md = [f"# Profile: {run.get('db')} {run.get('hosts')} hosts at {run.get('offered_rps')} posts/s, "
          f"{run.get('findings_per_bundle')} findings per bundle", "",
          f"Commit `{str(run.get('commit'))[:9]}`, box {run.get('box')}, wall {wall_s:.0f} s, "
          f"ingest p50 {run.get('p50_ms')} ms, p95 {run.get('p95_ms')} ms.", "",
          "## Top three costs (share of sampled wall time, self)", "",
          "| frame | self % | total % |", "|---|---|---|",
          *[f"| `{t['frame']}` | {t['self_pct']} | {t['total_pct']} |" for t in top3], "",
          f"Statements per ingest: **{s['statements_per_ingest']}** ({s['statements_note']}).", "",
          f"Slow event-loop callbacks (>= 100 ms): {s['slow_callbacks']['count']}, "
          f"max {s['slow_callbacks']['max_s']:.3f} s.", ""]
    (profile_dir / "summary.md").write_text("\n".join(md))
    return s
```

- [ ] **Step 4: Collector hooks in `_collector.py`**

`postgres_container(profile: bool = False)`: when `profile`, append to the `docker run` command `"-c", "shared_preload_libraries=pg_stat_statements", "-c", "pg_stat_statements.track=all", "-c", "session_preload_libraries=auto_explain", "-c", "auto_explain.log_min_duration=0", "-c", "auto_explain.log_analyze=on", "-c", "auto_explain.log_buffers=on"` after the image name (postgres accepts server flags as container args) and after the readiness loop run `CREATE EXTENSION IF NOT EXISTS pg_stat_statements`. Keep the container id in a module global `LAST_PG_CONTAINER` so the harness can `docker logs` it before the kill (register a `stack.callback` that writes `docker logs` to `profile_dir / "auto_explain.log"` and gzips it, before the kill callback).

`collector(db, workdir, enroll_token=ENROLL_TOKEN, profile_dir=None)`: when `profile_dir`:
- startup handler on the app: `async def _debug(): loop = asyncio.get_running_loop(); loop.set_debug(True); loop.slow_callback_duration = 0.1` via `app.add_event_handler("startup", _debug)`; a `logging.FileHandler(profile_dir / "asyncio-slow.log")` at WARNING on `logging.getLogger("asyncio")`, removed on exit.
- SQLite statement counts: find the `Repo` the app uses (grep `create_app` in `src/pqcscan/daemon/app.py` for where the repo is stored, e.g. `app.state.repo`; if it is only closed over, listen at class level: `sqlalchemy.event.listen(sqlalchemy.engine.Engine, "connect", _trace)` and in `_trace(dbapi_conn, _rec)` call `dbapi_conn.set_trace_callback(lambda sql: counter.update([_norm(sql)]))` when `hasattr(dbapi_conn, "set_trace_callback")`, with `_norm` = first 120 chars with runs of digits and quoted strings replaced by `?`). Dump `statements.json` on exit: `{"source": "sqlite3 trace callback", "total_statements": N, "top": [{"sql": ..., "count": ...} × 25]}`.
- Postgres statement counts on exit (before the container dies): `SELECT calls, total_exec_time, mean_exec_time, rows, left(query, 200) FROM pg_stat_statements WHERE query NOT ILIKE '%pg_stat_statements%' ORDER BY total_exec_time DESC LIMIT 25` and `SELECT sum(calls) FROM pg_stat_statements` → `statements.json` with `"source": "pg_stat_statements"`.

- [ ] **Step 5: `run_load --profile DIR`**

In `run(...)`: `profile_dir: Path | None = None`; pass to `_collector.collector(..., profile_dir=profile_dir)`; wrap the locust subprocess in `with _profile.pyspy(os.getpid(), profile_dir):` when profiling; after the result dict is built call `_profile.summarise(profile_dir, ingest_requests=result["requests"], enroll_requests=result["enroll_requests"], wall_s=duration_s, run=result)` and set `result["profile_dir"] = str(profile_dir.relative_to(REPO))` when under the repo. CLI `--profile DIR`. `benchmark/fleet/profiles/README.md`: what each file is, how to open the speedscope file (https://www.speedscope.app, drag the JSON), the ptrace requirement, and the exact command for a before/after pair.

- [ ] **Step 6: Local dry run with ptrace**

Run: `sudo -E env PATH=$PATH .venv/bin/python -m benchmark.fleet.run_load --db sqlite --hosts 10 --rate 1 --duration 30s --findings-per-bundle 200 --profile /tmp/claude-1000/-home-farzul-Projects-pqc-scanner2/998c29a9-000f-4315-9bb9-8d80d49c06ff/scratchpad/prof-dry --tag dry` (or set `kernel.yama.ptrace_scope=0` for the session). If neither is possible on this workstation, state so in the report; the real profiles run on the droplet as root (Task 3). Expected: `summary.md` with three frames and `statements_per_ingest` > 0. Delete the result row this dry run appended to LOAD.md and its result file (dry runs are not evidence).

- [ ] **Step 7: Tests, ruff, commit**

Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/benchmark/test_profile_summary.py tests/benchmark/test_fleet_load_smoke.py`; `.venv/bin/ruff check benchmark tests/benchmark`.
Commit: `feat(bench): --profile records py-spy, asyncio slow callbacks and statements per ingest`

---

### Task 3: Load box on DigitalOcean and the before-profiles

**Files:**
- Create: `benchmark/fleet/cloud/loadbox.sh`, `benchmark/fleet/cloud/loadbox-cloud-init.yaml`, `benchmark/fleet/cloud/suite.sh`, `benchmark/fleet/cloud/README.md`
- Create: `benchmark/fleet/profiles/sqlite-before/*`, `benchmark/fleet/profiles/postgres-before/*` (outputs)
- Modify: `benchmark/fleet/LOAD.md`, `benchmark/fleet/results/` (new rows/files)

**Interfaces:**
- Consumes: `run_load --rate --profile` (Tasks 1, 2); `doctl` logged in; an SSH key the controller creates (`~/.ssh/pqc_campaign_ed25519`, uploaded as `pqc-campaign`).
- Produces: `loadbox.sh up|run <mode>|wait|pull|down` with env `DO_REGION` (default `sgp1`), `DO_SIZE` (`s-8vcpu-16gb`), `DO_IMAGE` (`ubuntu-24-04-x64`), `DO_SSH_KEY` (name, default `pqc-campaign`), `PQC_REF` (commit to install); droplet name `pqc-loadbox`; `suite.sh before|after|sweep|ratio-baseline` run on the droplet writing to `benchmark/fleet/results/` and `profiles/` in the droplet's checkout; `pull` rsyncs those two directories and `LOAD.md` back into this checkout.

- [ ] **Step 1: `loadbox.sh`**

```bash
#!/usr/bin/env bash
# DigitalOcean load box for benchmark/fleet: create, run a suite, pull results, destroy.
#   loadbox.sh up            # create pqc-loadbox, wait for cloud-init, print IP
#   loadbox.sh run before    # run suite.sh <mode> on the box (nohup; log in /root/suite.log)
#   loadbox.sh wait          # block until the suite finished
#   loadbox.sh pull          # rsync results/, profiles/ and LOAD.md into this checkout
#   loadbox.sh down          # destroy the droplet
# Env: DO_REGION=sgp1 DO_SIZE=s-8vcpu-16gb DO_IMAGE=ubuntu-24-04-x64 DO_SSH_KEY=pqc-campaign PQC_REF=$(git rev-parse HEAD)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../../.." && pwd)
NAME=${DO_NAME:-pqc-loadbox}; REGION=${DO_REGION:-sgp1}; SIZE=${DO_SIZE:-s-8vcpu-16gb}
IMAGE=${DO_IMAGE:-ubuntu-24-04-x64}; KEY=${DO_SSH_KEY:-pqc-campaign}; REF=${PQC_REF:-$(git -C "$REPO" rev-parse HEAD)}
SSH="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 root@"
ip() { doctl compute droplet list --format Name,PublicIPv4 --no-header | awk -v n="$NAME" '$1==n{print $2}'; }
case "${1:-}" in
  up)
    keyid=$(doctl compute ssh-key list --format ID,Name --no-header | awk -v k="$KEY" '$2==k{print $1}')
    [ -n "$keyid" ] || { echo "ssh key $KEY not in DigitalOcean (doctl compute ssh-key import)"; exit 2; }
    sed "s|@PQC_REF@|$REF|" "$HERE/loadbox-cloud-init.yaml" > /tmp/pqc-loadbox-init.yaml
    doctl compute droplet create "$NAME" --region "$REGION" --size "$SIZE" --image "$IMAGE" --ssh-keys "$keyid" \
      --user-data-file /tmp/pqc-loadbox-init.yaml --tag-name pqc-campaign --wait >/dev/null
    for _ in $(seq 60); do sleep 10; $SSH"$(ip)" test -f /root/READY 2>/dev/null && break; done
    $SSH"$(ip)" test -f /root/READY || { echo "cloud-init did not finish; see /var/log/cloud-init-output.log"; exit 1; }
    echo "$(ip)";;
  run) $SSH"$(ip)" "cd /root/pqc-scanner2 && nohup bash benchmark/fleet/cloud/suite.sh ${2:?mode} > /root/suite.log 2>&1 & echo started";;
  wait) while ! $SSH"$(ip)" test -f /root/SUITE_DONE; do sleep 60; done; $SSH"$(ip)" tail -5 /root/suite.log;;
  pull) for p in results/ profiles/ LOAD.md; do
          rsync -az -e "ssh -o StrictHostKeyChecking=accept-new" "root@$(ip):/root/pqc-scanner2/benchmark/fleet/$p" "$REPO/benchmark/fleet/$p"; done;;
  down) doctl compute droplet delete -f "$NAME";;
  *) sed -n 2,8p "$0"; exit 2;;
esac
```

`loadbox-cloud-init.yaml` (`#cloud-config`): `package_update: true`, packages `docker.io git python3.12-venv rsync`, `runcmd`: `git clone https://github.com/orengacademy/pqc-scanner2 /root/pqc-scanner2`, `git -C /root/pqc-scanner2 checkout @PQC_REF@`, `python3 -m venv /root/pqc-scanner2/.venv`, `/root/pqc-scanner2/.venv/bin/pip install -e "/root/pqc-scanner2[dev,verify]" py-spy`, `docker pull postgres:16-alpine`, `touch /root/READY`.

`suite.sh` (runs on the box, `set -euo pipefail`, `cd /root/pqc-scanner2`, `PY=.venv/bin/python`, removes `/root/SUITE_DONE` first, touches it at the end):
- `before`: for db in sqlite postgres: `$PY -m benchmark.fleet.run_load --db $db --hosts 500 --rate 4 --duration 300s --profile benchmark/fleet/profiles/$db-before --tag before` (4 posts/s with 1,670-finding bundles saturates both backends per the PR #92 service times without hitting the 60 s timeout for most requests; if Postgres times out at 4, the profile is still valid and the summary says so).
- `after`: same with `--tag after` into `profiles/$db-after`.
- `sweep`: for db in sqlite postgres, for rate in 0.5 1 2 4 6 8 12, for seed in 1 2: `--hosts 500 --rate $rate --duration 300s --seed $seed --tag sweep`; then `--herd --hosts 500 --duration 180s --seed 1 --tag herd` per db.
- `ratio-baseline`: `--hosts 120 --interval 60 --duration 90s --findings-per-bundle 1670 --tag ci-shape` per db (the CI job's shape, for the page).
- `run_load` exits 1 on a FAIL row; the suite must continue (`|| true` per run) and still touch `SUITE_DONE`.

`cloud/README.md`: prerequisites (`doctl auth init`, an SSH key imported under a name, Docker not needed locally), the commands, the cost line (US$0.14 an hour for `s-8vcpu-16gb`), what `pull` overwrites, and the rule that a result from this box names the box in its `box` field.

- [ ] **Step 2: Controller: key and box**

Controller (not the implementer) runs: `ssh-keygen -t ed25519 -N '' -f ~/.ssh/pqc_campaign_ed25519 -C pqc-campaign`, `doctl compute ssh-key import pqc-campaign --public-key-file ~/.ssh/pqc_campaign_ed25519.pub`, then `DO_SSH_KEY=pqc-campaign bash benchmark/fleet/cloud/loadbox.sh up` with `PQC_REF` = the commit of this task pushed to origin (push the branch first). Add `IdentityFile ~/.ssh/pqc_campaign_ed25519` for the droplet IP in `~/.ssh/config` or export `GIT_SSH_COMMAND`-style via `SSH="ssh -i ..."`: the script honours `PQC_SSH_KEY` env (`-i`) when set.

- [ ] **Step 3: Run `before`, pull, inspect**

`loadbox.sh run before`, `loadbox.sh wait`, `loadbox.sh pull`. Read `profiles/sqlite-before/summary.md` and `profiles/postgres-before/summary.md`. Both must name three frames with shares and a statements-per-ingest figure; `asyncio-slow.log` exists (possibly empty). If py-spy produced no samples, fix the harness and rerun; do not hand-edit.

- [ ] **Step 4: Commit the scripts and the before-profiles**

Check no secrets: `grep -rn "token\|password" benchmark/fleet/profiles/*-before/summary.json` returns only field names. Commit: `bench(cloud): DigitalOcean load box; before-profiles at <commit> (sqlite, postgres, 500 hosts at 4 posts/s)`

---

### Task 4: Fixes the profile names, bounded ingest queue, FLEET.md overload behaviour

**Files:**
- Modify: `src/pqcscan/daemon/fleet.py`, `src/pqcscan/store/repo.py` (only frames the profile names), `docs/FLEET.md` (Ingest limits, Known limits)
- Test: `tests/unit/test_daemon_fleet.py` (new tests), `tests/unit/test_fleet_repo.py` (if repo changes)

**Interfaces:**
- Consumes: `benchmark/fleet/profiles/*-before/summary.md` (the evidence), `_TokenBucket`, `parse_slots`.
- Produces: `INGEST_QUEUE_MAX: int` in `daemon/fleet.py`; `503` with `Retry-After: 60` and detail `"collector busy: ingest queue full (N bundles); the agent spools and retries"` when the count of bundles waiting or parsing is at the bound; every performance change keeps `Repo.ingest_bundle`, `Repo.prune_host` signatures.

- [ ] **Step 1: Read both before-summaries; write the fix list**

For each of the top three frames per backend write one line in the commit plan: frame, share, the change, the test that pins behaviour. Allowed changes are bounded: e.g. `_bundle_drift` selecting only the columns `drift_rows` reads (`probe_id, algorithm, title, evidence`) as tuples instead of ORM rows; a Postgres-aware `INGEST_PARALLELISM` (SQLite has one writer; Postgres does not) exposed as `create_app(..., ingest_parallelism=None)` defaulting by dialect; `prune_host` deleting all evicted scans in one session. If the profile names something not on this list, fix that instead; if a top frame is locust or the OS (not the collector), say so in the summary and skip it. No change without a frame.

- [ ] **Step 2: Failing test for the bounded queue**

```python
# tests/unit/test_daemon_fleet.py (append)
import threading
import time

def test_ingest_queue_full_answers_503_with_retry_after(tmp_db_path, monkeypatch):
    from pqcscan.daemon import fleet as fleet_mod
    monkeypatch.setattr(fleet_mod, "INGEST_PARALLELISM", 1)
    monkeypatch.setattr(fleet_mod, "INGEST_QUEUE_MAX", 1)
    gate = threading.Event()
    real = fleet_mod.load_bundle
    def slow_load(data):
        gate.wait(10)            # hold the single parse slot until the test releases it
        return real(data)
    monkeypatch.setattr(fleet_mod, "load_bundle", slow_load)
    app = create_app(db_path=tmp_db_path, registry=Registry(), enroll_token="e")
    with TestClient(app) as c:
        tok = c.post("/api/agents/enroll", json={"enroll_token": "e", "host": {"machine_id": "m1"}}).json()["agent_token"]
        body = _bundle_bytes(machine_id="m1")          # the file's existing helper for a valid gzip bundle
        hdr = {"Authorization": f"Bearer {tok}", "Content-Type": "application/gzip"}
        results = []
        def post():
            results.append(c.post("/api/ingest", content=body, headers=hdr))
        ts = [threading.Thread(target=post) for _ in range(3)]
        for t in ts: t.start()
        time.sleep(0.5)                                   # let the three requests reach the queue
        gate.set()
        for t in ts: t.join(15)
    codes = sorted(r.status_code for r in results)
    assert codes.count(503) >= 1 and 200 in codes, codes
    shed = next(r for r in results if r.status_code == 503)
    assert shed.headers["Retry-After"] == "60" and "queue full" in shed.json()["detail"]
```

(Use the file's existing fixtures and bundle helper names; the three distinct bundles need distinct `scan_uuid`s only if the test asserts counts, which it does not.) TestClient runs the app in a thread per request with a shared loop; if the three requests do not overlap under TestClient, use `httpx.AsyncClient(transport=ASGITransport(app))` with `asyncio.gather` instead.

- [ ] **Step 3: Implement the bound**

```python
INGEST_QUEUE_MAX = 32   # bundles waiting for or holding a parse slot, all hosts. Longest wait ≈ QUEUE_MAX × service
                        # time / INGEST_PARALLELISM; at 2 s per large bundle and 2 slots that is 32 s, under the
                        # agent's 60 s timeout, so a queued request is served, never abandoned. Past the bound the
                        # collector answers 503 + Retry-After and the agent spools (FLEET.md, Ingest limits).
```

In `build_fleet_router`: `queued = 0` (closure `nonlocal`); in `ingest`, after the token-bucket check and before `_read_capped`: `if queued >= INGEST_QUEUE_MAX: raise HTTPException(503, f"collector busy: ingest queue full ({INGEST_QUEUE_MAX} bundles); the agent spools and retries", headers={"Retry-After": "60"})`; `queued += 1` then `try: ... async with parse_slots: ... finally: queued -= 1` around the parse-and-store block. (Single-threaded event loop: the counter needs no lock.) Read `INGEST_QUEUE_MAX` from the module at call time like the other constants so tests can patch it.

- [ ] **Step 4: Performance fixes, one commit each**

Each commit message: `perf(fleet): <change> — removes <frame> (<share>% self in profiles/<db>-before)`. Existing tests must stay green: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_daemon_fleet.py tests/unit/test_fleet_repo.py tests/unit/test_parity_drift.py tests/unit/test_fleet_threat_model_gaps.py tests/integration/test_fleet_e2e.py tests/integration/test_fleet_spool.py`, and once on Postgres: `docker run --rm -d --name pqc-pg-test -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=pqc postgres:16-alpine`, `PQCSCAN_TEST_DB_URL=postgresql+psycopg://postgres:pqc@127.0.0.1:55432/postgres PQCSCAN_REQUIRE_POSTGRES=1 .venv/bin/python -m pytest -q -p no:cacheprovider <same files + tests/unit/test_db_dialect.py>`, then `docker kill pqc-pg-test`.

- [ ] **Step 5: FLEET.md**

Ingest limits bullet: add "The collector parses and stores two bundles at a time and queues at most 32 more; past that it answers `503` with `Retry-After: 60` without reading the body, and the agent spools the bundle and sends it on its next run. A queued bundle waits at most about half a minute, so no request is abandoned at the agent's 60 s timeout." Known limits, Ingest capacity bullet: replace the PR #92 band paragraph with a placeholder sentence that Task 5 fills with the measured λ_max (keep one line of history: the PR #92 rows ran on a shared box at 8.3 posts/s, 30 times FLEET.md's 2,000-host rate). Known limits, Postgres bullet: replace "nobody has profiled why" with "profiled in `benchmark/fleet/profiles/postgres-before`: <top frame> was <share>%; after <commit> it is <share>%" (fill from the after-profile in Task 5 if not yet available; leave a `TODO(task5)` marker that Task 5 must remove).

- [ ] **Step 6: Ruff, mypy, commit**

Run: `.venv/bin/ruff check src tests benchmark && .venv/bin/mypy src`. Commit the queue separately: `feat(fleet): bounded ingest queue, 503 + Retry-After past 32 waiting bundles`. The FLEET.md text goes with it.

---

### Task 5: After-profiles, capacity sweep, CAPACITY.md

**Files:**
- Create: `benchmark/fleet/CAPACITY.md`, `benchmark/fleet/capacity.py`
- Create: `benchmark/fleet/profiles/sqlite-after/*`, `profiles/postgres-after/*`, sweep result files
- Modify: `benchmark/fleet/LOAD.md`, `docs/FLEET.md` (capacity sentence, Postgres sentence; remove the `TODO(task5)` marker)
- Test: `tests/benchmark/test_capacity.py`

**Interfaces:**
- Consumes: `loadbox.sh run after|sweep|ratio-baseline` on a box rebuilt at the Task 4 commit (`loadbox.sh down && PQC_REF=<task4 commit> loadbox.sh up`, after pushing).
- Produces: `capacity.py` → `benchmark/fleet/CAPACITY.md` from `results/load-*-sweep*.json`: `capacity(results: list[dict]) -> dict` with per db `{"lambda_max": float, "band": [pass_rate, fail_rate], "hosts_daily_2h": int, "hosts_daily_24h": int, "rows": [...], "excluded": [...]}`; rule: λ_max = largest rate at which both seeds pass p95 < 2 s with `measurement_defect == False`; band upper = smallest rate at which any seed fails or is a defect; translations `hosts_daily_2h = λ_max × 7200`, `hosts_daily_24h = λ_max × 86400`.

- [ ] **Step 1: Failing test for `capacity()`**

```python
# tests/benchmark/test_capacity.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import capacity

def row(db, rate, seed, p95, defect=False):
    return {"db": db, "offered_rps": rate, "seed": seed, "p95_ms": p95, "pass_p95_lt_2s": p95 < 2000,
            "measurement_defect": defect, "arrival": "staggered", "requests": 100}

def test_lambda_max_needs_both_seeds_and_no_defect():
    rows = [row("sqlite", 1, 1, 300), row("sqlite", 1, 2, 320),
            row("sqlite", 2, 1, 900), row("sqlite", 2, 2, 950),
            row("sqlite", 4, 1, 1500), row("sqlite", 4, 2, 2600),
            row("sqlite", 8, 1, 9000, defect=True), row("sqlite", 8, 2, 9500, defect=True)]
    c = capacity.capacity(rows)["sqlite"]
    assert c["lambda_max"] == 2 and c["band"] == [2, 4]
    assert c["hosts_daily_2h"] == 14400 and c["hosts_daily_24h"] == 172800
    assert [r["offered_rps"] for r in c["excluded"]] == [8, 8]
```

- [ ] **Step 2: Implement `capacity.py`** (reads `results/load-*.json` whose filename carries `-sweep` or `-herd`, groups by db and rate, applies the rule, writes `CAPACITY.md` with: the method paragraph (open arrival at λ with 500 distinct hosts, 1,670-finding bundles, 300 s, two seeds, Little's law exclusion), one table per backend (rate, seed, requests, p50, p95, p99, achieved rps, Little ratio, 429, 503, errors, pass), the λ_max line with band and translations, the herd rows (503 count, timeouts, p95) and one paragraph reinterpreting the PR #92 rows: "500 hosts every 60 s was 8.3 posts/s, about 60,000 daily hosts under FLEET.md's timer; at FLEET.md's 2,000 hosts the offered rate is 0.28 posts/s"). CLI: `python -m benchmark.fleet.capacity` regenerates the file.

- [ ] **Step 3: Rebuild the box at the Task 4 commit and run `after` then `sweep`**

Push the branch. `bash benchmark/fleet/cloud/loadbox.sh down; PQC_REF=$(git rev-parse HEAD) bash benchmark/fleet/cloud/loadbox.sh up; loadbox.sh run after; loadbox.sh wait; loadbox.sh run sweep; loadbox.sh wait; loadbox.sh run ratio-baseline; loadbox.sh wait; loadbox.sh pull`. About 3 hours. Then `loadbox.sh down`.

- [ ] **Step 4: Regenerate CAPACITY.md, fill FLEET.md**

`.venv/bin/python -m benchmark.fleet.capacity`. FLEET.md Known limits, Ingest capacity: "Measured on an 8-vCPU DigitalOcean droplet (`benchmark/fleet/CAPACITY.md`): the collector sustains λ_max = X posts/s on SQLite (band X to Y) and Z on Postgres with 1,670-finding bundles at p95 < 2 s. Under the daily timer with a 2 h jitter that is about N hosts (SQLite) and M (Postgres); FLEET.md's 2,000 hosts offer 0.28 posts/s. A herd of 500 hosts at once gets K `503`s and no timeouts." Postgres sentence filled from the after-profile; remove `TODO(task5)`. Each after-profile `summary.md` gains one line under the table: "Before: <frame> <share>% (profiles/<db>-before)".

- [ ] **Step 5: Tests, ruff, commit**

`.venv/bin/python -m pytest -q -p no:cacheprovider tests/benchmark/test_capacity.py`; `.venv/bin/ruff check benchmark`. Commit: `bench: after-profiles, capacity sweep on the load box, CAPACITY.md; FLEET.md states measured capacity`

---

### Task 6: CI `load-ratio` job and `ratio.py`

**Files:**
- Create: `benchmark/fleet/ratio.py`
- Modify: `.github/workflows/verify.yml` (new job `load-ratio`)
- Create: `benchmark/fleet/results/ci-baseline-sqlite.json`, `ci-baseline-postgres.json` (from the first green run's artifacts)
- Test: `tests/benchmark/test_ratio.py`

**Interfaces:**
- Produces: `python -m benchmark.fleet.ratio BASE.json HEAD.json --max-ratio 1.5 --floor-ms 1000` exits 0 when `head_p95 <= max(max_ratio × base_p95, floor_ms)`, else 1; prints a three-row table (base, head, ratio) for p50, p95, rps, errors. `ratio.verdict(base: Path, head: Path, *, max_ratio: float, floor_ms: float) -> int`.

- [ ] **Step 1: Failing test**

```python
# tests/benchmark/test_ratio.py
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import ratio

def _w(p, p95): p.write_text(json.dumps({"p50_ms": 100, "p95_ms": p95, "rps": 2.0, "errors": 0})); return p

def test_ratio_passes_under_floor_and_fails_past_ratio(tmp_path):
    base = _w(tmp_path / "b.json", 400)
    assert ratio.verdict(base, _w(tmp_path / "h1.json", 900), max_ratio=1.5, floor_ms=1000) == 0   # 2.25x but < 1 s
    assert ratio.verdict(base, _w(tmp_path / "h2.json", 1200), max_ratio=1.5, floor_ms=1000) == 1  # 3x and > 1 s
    assert ratio.verdict(_w(tmp_path / "b2.json", 1500), _w(tmp_path / "h3.json", 2000), max_ratio=1.5, floor_ms=1000) == 0
```

- [ ] **Step 2: Implement `ratio.py`** (argparse, `verdict`, table print).

- [ ] **Step 3: Workflow job**

```yaml
  load-ratio:
    # Same-runner A/B: the harness at 120 hosts, 60 s interval (2 posts/s), 1,670-finding bundles, 90 s, on SQLite
    # and Postgres, from the baseline commit (PR #92 head) and from HEAD. Fails when HEAD p95 exceeds both 1.5 x
    # baseline and 1 s. Postgres runs in a container the harness starts itself (docker is on ubuntu-latest).
    runs-on: ubuntu-latest
    timeout-minutes: 40
    env:
      BASE_REF: 77867a1
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: { ref: ${{ env.BASE_REF }}, path: baseline }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python -m venv .venv-head && .venv-head/bin/pip install -e ".[dev,verify]"
      - run: python -m venv .venv-base && .venv-base/bin/pip install -e "./baseline[dev,verify]"
      - name: Run both on both backends
        run: |
          set -e
          for db in sqlite postgres; do
            (cd baseline && ../.venv-base/bin/python -m benchmark.fleet.run_load --db $db --hosts 120 --interval 60 --duration 90s --findings-per-bundle 1670 --tag ci-base | tail -1 >/dev/null)
            .venv-head/bin/python -m benchmark.fleet.run_load --db $db --hosts 120 --interval 60 --duration 90s --findings-per-bundle 1670 --tag ci-head | tail -1 >/dev/null
            base=$(ls -t baseline/benchmark/fleet/results/load-$db-*-ci-base*.json | head -1)
            head=$(ls -t benchmark/fleet/results/load-$db-*-ci-head*.json | head -1)
            .venv-head/bin/python -m benchmark.fleet.ratio "$base" "$head" --max-ratio 1.5 --floor-ms 1000
          done
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: load-ratio-results, path: "benchmark/fleet/results/*ci-*.json baseline/benchmark/fleet/results/*ci-*.json" }
```

(The baseline harness has `--interval` and `--findings-per-bundle`; it has no `--rate`, hence `--interval 60` on both sides. `run_load` exits 1 when p95 >= 2 s; the `| tail -1` swallows the exit code on purpose: the ratio is the gate, and the job comment says so.) Push, let `verify.yml` run, download the artifact, commit the two HEAD JSONs as `ci-baseline-<db>.json` with a `"note"` key added: "first load-ratio run, runner ubuntu-latest, run id N".

- [ ] **Step 4: Test, ruff, commit**

Commit: `ci(verify): load-ratio job, same-runner A/B against 77867a1; ratio.py`

---

### Task 7: Real soak infrastructure and launch

**Files:**
- Create: `benchmark/fleet/cloud/soak.sh`, `benchmark/fleet/cloud/soak-collector-init.yaml`, `benchmark/fleet/cloud/soak-agent-init.sh`, `benchmark/fleet/cloud/sampler.sh`
- Create: `.github/workflows/soak-windows.yml`
- Modify: `benchmark/fleet/soak-real.md` (rewrite to this procedure), `benchmark/fleet/soak.py` (only if `--observe` needs a flag to read a copied SQLite file; it already takes a path)
- Test: `tests/benchmark/test_soak_scripts.py` (static checks: scripts parse with `bash -n`, the workflow YAML loads, the sampler header matches the collect parser)

**Interfaces:**
- Produces: `soak.sh up` creates `pqc-soak-collector` (`s-2vcpu-4gb`, `ubuntu-24-04-x64`) and `pqc-soak-ubuntu`, `pqc-soak-debian`, `pqc-soak-rocky` (`s-1vcpu-1gb`; images `ubuntu-24-04-x64`, `debian-12-x64`, `rockylinux-9-x64`), tag `pqc-campaign`; prints the collector URL, and writes `~/.config/pqc-soak/env` (mode 0600, outside the repo) with `SOAK_SERVER_URL`, `SOAK_SITE_TOKEN`, `SOAK_ENROLL_TOKEN`, `SOAK_CA_PEM_PATH`. `soak.sh status` prints `/api/fleet` through the site token (host, last_seen, drift). `soak.sh collect` rsyncs `/var/lib/pqcscan-soak/samples.csv` from every droplet into `benchmark/fleet/results/soak-real/<droplet>-samples.csv`, copies the collector DB (`sqlite3 fleet.db ".backup /tmp/fleet-copy.db"` on the droplet, then scp) and runs `python -m benchmark.fleet.soak --observe --db <copy> --out benchmark/fleet/results/soak-real-<YYYYMMDD>.json` (check `soak.py --observe`'s actual flag names first and use them), plus `journalctl -u pqcscan-collector --since -8d -o short-iso` into `results/soak-real/collector-journal.log.gz` with tokens redacted. `soak.sh down` destroys the four droplets.
- Collector droplet: cloud-init installs `python3.12-venv git sqlite3 ufw`, clones at `@PQC_REF@`, venv at `/opt/pqcscan`, generates a CA and a server cert (`openssl req -x509` CA; server key + CSR with `subjectAltName = IP:<public ip>`, signed by the CA, 30 days), writes `/etc/pqcscan/collector.env` (0600: `PQCSCAN_TOKEN`, `PQCSCAN_ENROLL_TOKEN` from `openssl rand -hex 24`), installs `pqcscan-collector.service` (`ExecStart=/opt/pqcscan/bin/pqcscan daemon --bind 0.0.0.0 --port 8765 --db /var/lib/pqcscan/fleet.db --tls-cert /etc/pqcscan/server.pem --tls-key /etc/pqcscan/server.key --allow-host <public ip> --keep-scans-per-host 12`, `EnvironmentFile=/etc/pqcscan/collector.env`, `User=pqcscan`, `Restart=on-failure`), `ufw allow 22,8765/tcp`, installs `sampler.sh` as a cron `*/10 * * * *`, and `soak.sh up` fetches `/etc/pqcscan/ca.pem` and the env file over scp.
- Agent droplets (`soak-agent-init.sh`, run over ssh after creation because Rocky's cloud-init package set differs): detect distro; install Python ≥ 3.11 (`apt install python3-venv git` on Ubuntu/Debian; `dnf install python3.12 git` on Rocky); `python3 -m venv /opt/pqcscan && /opt/pqcscan/bin/pip install "git+https://github.com/orengacademy/pqc-scanner2@<PQC_REF>"`; `ln -s /opt/pqcscan/bin/pqcscan /usr/local/bin/pqcscan`; `useradd --system --home-dir /var/lib/pqcscan --shell /usr/sbin/nologin pqcscan` (`/sbin/nologin` on Rocky); copy `ca.pem` to `/etc/pqcscan/ca.pem`; write `/etc/pqcscan/agent.env` (0600: `PQCSCAN_SERVER`, `PQCSCAN_LABELS=env=soak,os=<distro>`, `PQCSCAN_ENROLL_TOKEN`); install the shipped `packaging/fleet/pqcscan-agent.service` and `.timer` verbatim plus a drop-in `/etc/systemd/system/pqcscan-agent.service.d/ca.conf` with `ExecStart=` reset and the same line plus `--ca-cert /etc/pqcscan/ca.pem` (FLEET.md says to append it); `systemctl enable --now pqcscan-agent.timer`; `systemctl start pqcscan-agent.service` (day-0 run); cron `sampler.sh` every 10 minutes.
- `sampler.sh`: appends one CSV line to `/var/lib/pqcscan-soak/samples.csv` with `HEADER="ts,role,load1,mem_used_kb,mem_avail_kb,disk_used_kb,db_bytes,wal_bytes,state_bytes,spool_files,hosts,scans,findings"` (collector fills db/wal/hosts/scans/findings via `sqlite3 -readonly "file:/var/lib/pqcscan/fleet.db?mode=ro"`; agents fill state/spool; `vmstat 1 2 | tail -1` for memory, `/proc/loadavg` for load, `df --output=used /var/lib` for disk; `ts` is ISO 8601 UTC `date -u +%FT%TZ`).
- `.github/workflows/soak-windows.yml`: `on: schedule: - cron: "0 2 * * *"`, `workflow_dispatch`; `jobs.agent`: `strategy.matrix.os: [windows-2022, windows-latest]`, `fail-fast: false`; steps: checkout `ref: ${{ vars.SOAK_REF }}` (a repository variable the controller sets to the campaign commit), setup-python 3.11, `pip install -e ".[build]"`, build with the release spec (copy the Windows build step from `release.yml`), `Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography -Name MachineGuid -Value ${{ matrix.os == 'windows-2022' && '6b1f0c2e-0000-4000-8000-000000002022' || '6b1f0c2e-0000-4000-8000-000000002025' }}`, `actions/cache/restore` (`path: ${{ runner.temp }}\pqc-state`, `key: soak-state-${{ matrix.os }}-${{ github.run_id }}`, `restore-keys: soak-state-${{ matrix.os }}-`), write `ca.pem` from `secrets.SOAK_CA_PEM`, `Start-Sleep -Seconds (Get-Random -Maximum 1800)` (jitter), `dist\pqcscan.exe agent --once --server $env:SOAK_SERVER_URL --enroll-token $env:SOAK_ENROLL_TOKEN --ca-cert ca.pem --labels env=soak,os=windows,runner=${{ matrix.os }} --state-dir $env:RUNNER_TEMP\pqc-state 2>&1 | Tee-Object agent.log`, `actions/cache/save` (same key), upload `agent.log` and a `Get-ChildItem -Recurse` listing of the state dir as an artifact. Secrets: `SOAK_SERVER_URL`, `SOAK_ENROLL_TOKEN`, `SOAK_CA_PEM` (set by the controller with `gh secret set` from `~/.config/pqc-soak/env`); variable `SOAK_REF` via `gh variable set`.

- [ ] **Step 1: Static tests first**

```python
# tests/benchmark/test_soak_scripts.py
import subprocess
from pathlib import Path
import yaml

CLOUD = Path(__file__).resolve().parents[2] / "benchmark/fleet/cloud"

def test_shell_scripts_parse():
    for s in ("soak.sh", "soak-agent-init.sh", "sampler.sh", "loadbox.sh", "suite.sh"):
        subprocess.run(["bash", "-n", str(CLOUD / s)], check=True)

def test_windows_soak_workflow_loads_and_pins_identity():
    wf = yaml.safe_load((CLOUD.parents[2] / ".github/workflows/soak-windows.yml").read_text())
    assert wf[True]["schedule"] == [{"cron": "0 2 * * *"}]        # PyYAML parses `on` as True
    steps = "\n".join(str(s) for s in wf["jobs"]["agent"]["steps"])
    assert "MachineGuid" in steps and "actions/cache/restore" in steps and "--once" in steps

def test_sampler_header_matches_collect_parser():
    header = [ln for ln in (CLOUD / "sampler.sh").read_text().splitlines() if ln.startswith("HEADER=")][0]
    assert "ts,role,load1,mem_used_kb,mem_avail_kb,disk_used_kb,db_bytes,wal_bytes,state_bytes,spool_files,hosts,scans,findings" in header
```

- [ ] **Step 2: Write the scripts, the workflow, and `soak-real.md`**

`soak-real.md` sections: what runs where (table of the five hosts, image, size, scheduler, how identity is pinned), the FLEET.md predictions to compare against (one row each: ingests per host per day = 1; drift rows per host per day = 0 after day 1 unless the host changed; 429 = 0; 503 = 0; duplicates = 0; prune count = 0 until day 13; DB growth per host per scan ≈ 1.2 MB; token refreshes = 0; stale flag = none), the four commands, the day-7 procedure, the cost, teardown, and what is untested (Windows 11, IBM i, a persistent Windows disk).

- [ ] **Step 3: Controller launches**

Push the branch (Task 4 commit or later). `PQC_REF=$(git rev-parse HEAD) bash benchmark/fleet/cloud/soak.sh up`; `gh secret set SOAK_SERVER_URL`, `SOAK_ENROLL_TOKEN`, `SOAK_CA_PEM` from the env file; `gh variable set SOAK_REF`; `gh workflow run soak-windows.yml`; wait for both Windows jobs; `soak.sh status` must list five hosts with a `last_seen` today. If a Linux agent did not enroll, read `journalctl -u pqcscan-agent` on it and fix the init script (not the agent) unless the agent is at fault, which is a finding.

- [ ] **Step 4: Day-0 collect and commit**

`bash benchmark/fleet/cloud/soak.sh collect` → `results/soak-real-<date>.json` and the sample CSVs. Confirm no token in any committed file (`grep -rn "$SOAK_ENROLL_TOKEN" benchmark/ docs/` empty; the journal is redacted). Commit: `bench(soak): real soak launched <date> (collector + 3 Linux droplets + 2 Windows runners); day-0 observe`

---

### Task 8a: Mutation and fuzz harnesses, background launch

**Files:**
- Modify: `pyproject.toml` (`verify` extra adds `mutmut>=3.2`, `atheris>=2.3; sys_platform == 'linux'`, `coverage>=7`; `[tool.mutmut]` table), `.gitignore` (`mutants/`, `benchmark/fleet/fuzz/work/`)
- Create: `benchmark/fleet/mutation/run.sh`, `benchmark/fleet/mutation/README.md`
- Create: `benchmark/fleet/fuzz/__init__.py`, `fuzz_load_bundle_raw.py`, `fuzz_load_bundle_json.py`, `seed.py`, `bundle.dict`, `run.sh`, `replay.py`, `replay_coverage.sh`, `README.md`
- Test: `tests/benchmark/test_fuzz_harness_smoke.py`

**Interfaces:**
- Produces: `[tool.mutmut] paths_to_mutate = ["src/pqcscan/daemon/fleet.py", "src/pqcscan/store/bundle.py"]`, `tests_dir = ["tests/unit"]`, `do_not_mutate = []`; `mutation/run.sh` → `mutation/results.txt` (`mutmut results`), `mutation/survivors/<id>.diff` (`mutmut show <id>` per survivor), `mutation/score.json` (`{"killed", "survived", "timeout", "suspicious", "total", "score"}` parsed from the results); `fuzz/run.sh [cpu_hours]` → `fuzz/work/<harness>/` (corpus, crashes), then `-merge=1` into `fuzz/corpus/<harness>/`, then `replay_coverage.sh` → `fuzz/coverage.txt` and `fuzz/stats.json` (`{"harness", "cpu_seconds", "execs", "crashes", "corpus_files"}`).

- [ ] **Step 1: Harnesses**

```python
# benchmark/fleet/fuzz/fuzz_load_bundle_json.py
"""libFuzzer target: the input is the bundle JSON text; it is gzipped and fed to load_bundle, so the fuzzer works
on the parser and the validators rather than on gzip. Expected rejections are BundleInvalid and BundleTooLarge;
anything else is a crash."""
import gzip
import sys

import atheris

with atheris.instrument_imports(include=["pqcscan.store.bundle", "pqcscan.core.parity"]):
    from pqcscan.store.bundle import BundleInvalid, BundleTooLarge, load_bundle


def TestOneInput(data: bytes) -> None:
    try:
        load_bundle(gzip.compress(data, compresslevel=1))
    except (BundleInvalid, BundleTooLarge):
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```

`fuzz_load_bundle_raw.py`: same without the gzip step. `seed.py`: writes `seeds/json/` (3 valid bundle documents from `_bundles.build_template(n_findings=3)` with `labels`, one with `views`, one `status: failed`) and `seeds/raw/` (the same gzipped). `bundle.dict`: the JSON keys `load_bundle` reads (read them from `src/pqcscan/store/bundle.py`: `"scan_uuid"`, `"host"`, `"machine_id"`, `"hostname"`, `"os"`, `"labels"`, `"agent_version"`, `"scan"`, `"status"`, `"started_at"`, `"finished_at"`, `"findings"`, `"probe_id"`, `"algorithm"`, `"severity"`, `"classification"`, `"evidence"`, `"views"`, `"framework"`, `"clause"`, `"verdict"`, `"deadline"`, `"done"`, `"failed"`, `"fleet.drift"`) and a few values. `run.sh`: `H=${1:-4}`; per harness `.venv/bin/python fuzz_<h>.py work/<h>/corpus seeds/<h> -dict=bundle.dict -jobs=4 -workers=4 -max_total_time=$((H*3600/2/4)) -max_len=262144 -rss_limit_mb=4096 -timeout=30 -artifact_prefix=work/<h>/` (two harnesses share the hours; 4 workers → CPU-hours = 4 × wall), then `-merge=1 corpus/<h> work/<h>/corpus seeds/<h>`, then `replay_coverage.sh` (`coverage run --include='src/pqcscan/store/bundle.py,src/pqcscan/core/parity.py' -m benchmark.fleet.fuzz.replay corpus/` where `replay.py` calls `load_bundle` on each file, gzipping the json corpus; `coverage report -m > coverage.txt`), and `stats.json` from the fuzzer logs (`#<execs>` and `cov:` from the last status line per job, crash files counted).

- [ ] **Step 2: Smoke test** (`tests/benchmark/test_fuzz_harness_smoke.py`): `importorskip("atheris")`; run `fuzz_load_bundle_json.py` as a subprocess with `-runs=200 <tmp seeds>` after `seed.py` into a tmp dir; assert exit 0 and no `crash-*` file. Mark `benchmark`.

- [ ] **Step 3: Mutation config and runner**

`mutation/run.sh`: `cd $REPO; rm -rf mutants; .venv/bin/mutmut run 2>&1 | tee benchmark/fleet/mutation/run.log; .venv/bin/mutmut results > benchmark/fleet/mutation/results.txt;` then a small Python block that parses `results.txt` into `score.json` and writes `survivors/*.diff` via `mutmut show <id>`. mutmut 3 copies `src` into `mutants/` and runs pytest from there, so the run must not be concurrent with other test runs in this checkout; say so in README. Check the installed mutmut's CLI once (`mutmut --help`) and use its real flag and subcommand names; record the version in README.

- [ ] **Step 4: Install, verify each tool starts, commit**

`uv pip install -e ".[dev,verify]"`; `.venv/bin/mutmut --version`; `.venv/bin/python -c "import atheris"`; run the smoke test. Commit: `bench: mutmut config and runner; atheris harnesses, seeds and dictionary for load_bundle`

- [ ] **Step 5: Controller launches both runs in the background on this box**

`nohup bash benchmark/fleet/fuzz/run.sh 4 > benchmark/fleet/fuzz/run.log 2>&1 &` and, after the fuzz run has started, `nohup bash benchmark/fleet/mutation/run.sh > /dev/null 2>&1 &`.

---

### Task 8b: Mutation and fuzz write-up, survivors killed or justified

**Files:**
- Create: `benchmark/fleet/mutation/MUTATION.md`, `benchmark/fleet/fuzz/FUZZ.md`
- Modify: `tests/unit/test_daemon_fleet.py`, the bundle unit test file (find it: `grep -ln "load_bundle" tests/unit/*.py`) with killing tests
- Commit: `benchmark/fleet/fuzz/corpus/**`, `benchmark/fleet/fuzz/coverage.txt`, `stats.json`, `mutation/results.txt`, `score.json`, `survivors/*.diff`

- [ ] **Step 1: Wait for both runs** (`benchmark/fleet/fuzz/stats.json` and `benchmark/fleet/mutation/score.json` exist).

- [ ] **Step 2: Survivors in auth, token bucket, size caps**

For each `survivors/<id>.diff` whose hunk touches `_TokenBucket`, `_agent_host`, `enroll` (token compare, revoked, labels), `_read_capped`, `MAX_*`/`INGEST_*` constants, `check_labels`, size caps in `load_bundle`: write a test that fails on the mutant and passes on the code (run `mutmut run <id>` to confirm the kill), or write a one-line justification why the mutant is equivalent (e.g. a log string). Table in `MUTATION.md`: id, file:line, mutation, verdict (killed by `test_x` / equivalent: reason / open). Rerun `mutmut run` only for those ids. Score line: killed / (total − equivalent), with the raw numbers next to it.

- [ ] **Step 3: `FUZZ.md`**: per harness CPU-hours (workers × wall), executions, crashes (each one a finding: minimal input committed under `fuzz/crashes/`, the fix in its own commit with a regression test in `tests/fuzz` or `tests/unit`), corpus files, coverage of `store/bundle.py` and `core/parity.py` with the uncovered lines listed, and the exact `run.sh` command.

- [ ] **Step 4: Commit**: `test(fleet): mutation survivors killed; FUZZ.md and MUTATION.md with corpus, coverage and score`

---

### Task 9: Contradicted claim F6 — `windows-task.ps1` with a non-SYSTEM `-RunAs`

**Files:**
- Modify: `packaging/fleet/windows-task.ps1`, `packaging/fleet/windows-task.Tests.ps1`, `docs/FLEET.md` (Recipes table row for `windows-task.ps1`)

**Interfaces:**
- Consumes: the Pester case that asserts the non-SYSTEM failure (find it: `grep -n "RunAs" packaging/fleet/windows-task.Tests.ps1`), FLEET-EVIDENCE F6.
- Produces: one of two behaviours, chosen from the root cause: (a) registration succeeds for a service-style account (gMSA / virtual account: `New-ScheduledTaskPrincipal -UserId $RunAs -LogonType Password` for a gMSA, `-LogonType ServiceAccount` for `NT SERVICE\` virtual accounts) and the state folder ACL grants it Modify as FLEET.md says; or (b) the script resolves and validates the account and refuses with a clear message before any folder, binary or file is written. Pester pins whichever: for (b) `Test-Path` on `%ProgramFiles%\pqcscan` and `%ProgramData%\pqcscan` is false after the refusal and the exit is non-zero; for (a) `Get-ScheduledTask` shows the principal and `Get-Acl` the Modify right.

- [ ] **Step 1: Read the failing Pester case and the script's `Register-ScheduledTask` call; reproduce the error text from the last `windows-installer` run log (`gh run view <id> --log | grep -i runas`).**
- [ ] **Step 2: Decide (a) or (b) from the error.** A plain local user needs a password the script cannot take safely → (b) for plain users; a gMSA or `NT SERVICE\` account needs only the right `LogonType` → (a) for those if the fix is under 20 lines; otherwise (b) for all non-SYSTEM accounts with the message naming the supported principals. Record the choice in the commit body.
- [ ] **Step 3: Change the Pester case from "asserts the failure" to "asserts the chosen behaviour"; add the no-files-written assertion for (b).**
- [ ] **Step 4: FLEET.md Recipes row: one sentence stating which `-RunAs` principals are supported and what happens otherwise.**
- [ ] **Step 5: Push and watch `verify.yml` job `windows-installer` on both runners; green on both before the task is done.** Commit: `fix(packaging): windows-task.ps1 <refuses|supports> non-SYSTEM -RunAs before writing; Pester pins it (F6)`

---

### Task 10: Evidence page "Since PR #92", docs, status

**Files:**
- Modify: `docs/FLEET-EVIDENCE.md` (new top section, item verdicts, claim rows, findings), `docs/FLEET.md` (final read-through), `docs/STATUS.md`, `docs/TODO.md`, `CHANGELOG.md` (Unreleased), `benchmark/fleet/README.md`

- [ ] **Step 1: "Since PR #92" section at the top of FLEET-EVIDENCE.md**, under one page: a table of every claim whose status changed (section, claim, old status, new status, artefact), the six item verdicts of this campaign (1 profile: done, top three per backend with before/after shares; 2 capacity: λ_max per backend with band and translations; 3 overload: 503 path tested, herd result; 4 soak: running since <date>, day 0 recorded, day 7 on <date>, hosts listed, Windows 11 and IBM i untested; 5 strength: mutation score, survivors killed/justified, fuzz CPU-hours, crashes, coverage; 6 contradicted: F6 resolution, Postgres profiled), new findings F21+ (anything the profile, sweep, herd, soak day 0, mutation or fuzz turned up), and the tag decision: v0.10.3 waits for day 7 of the soak; the commands a stranger runs (`loadbox.sh up/run sweep/pull`, `python -m benchmark.fleet.capacity`, `soak.sh collect`).
- [ ] **Step 2: Regrade the affected rows in the main table** (Scale rows, Ingest capacity, Postgres, Recipes/F6) and update the findings table (F7 capacity → measured; F19 bundle size → measured with 1,670; F6 → fixed or restated; Postgres unprofiled → profiled).
- [ ] **Step 3: FLEET.md read-through**: Ingest limits, Ingest capacity, Postgres, Recipes rows all consistent with CAPACITY.md and the profiles; no `TODO(task5)` left (`grep -rn "TODO(task" docs benchmark` empty).
- [ ] **Step 4: STATUS.md** test count at the final commit; **TODO.md** Postgres item updated, soak day-7 item added with the date; **CHANGELOG.md** Unreleased: perf fixes (each with its frame), bounded ingest queue, installer fix, harness changes.
- [ ] **Step 5: Full suite once (no load or fuzz run active)**: `.venv/bin/python -m pytest -q -p no:cacheprovider`; `.venv/bin/ruff check src tests benchmark`; `.venv/bin/mypy src`. Commit: `docs(fleet-evidence): Since PR #92 — regrades, capacity, soak day 0, test strength, F6`

---

### Task 11: Fleet web UI at fleet scale, reviewed in a real browser

**Files:**
- Create: `benchmark/fleet/make_fleet_db.py` (offline 500-host SQLite DB from the harness bundles), `benchmark/fleet/ui/` (screenshots, timings JSON), `docs/FLEET-UI-REVIEW.md`
- Modify (defect fixes only, no features): `src/pqcscan/ui/templates/fleet*.html`, `src/pqcscan/ui/static/*`, `src/pqcscan/daemon/app.py` fleet routes if a measured defect lives there
- Test: `tests/benchmark/test_make_fleet_db.py` (10 hosts, asserts host and scan counts through `Repo`)

**Interfaces:**
- Consumes: `benchmark/fleet/_bundles.build_template`, `host_bundle`, `pqcscan.store.bundle.load_bundle`, `Repo.upsert_host`, `Repo.ingest_bundle`; `pqcscan daemon --db <file> --bind 127.0.0.1 --port <free>`; Chrome DevTools MCP (`new_page`, `navigate_page`, `take_screenshot`, `performance_start_trace`/`stop_trace`, `lighthouse_audit`, `take_snapshot`) and Playwright MCP (`browser_navigate`, `browser_snapshot`, `browser_take_screenshot`).
- Produces: `python -m benchmark.fleet.make_fleet_db --hosts 500 --scans-per-host 2 --findings 1670 --out <db>`; `benchmark/fleet/ui/timings.json` (`{"page": "/fleet", "hosts": 500, "ttfb_ms", "dom_content_loaded_ms", "load_ms", "transfer_bytes", "lighthouse": {...}}` per page); screenshots `fleet-500-desktop.png`, `fleet-500-mobile.png`, `fleet-host.png`, `fleet-filter.png`; the review document with one row per finding (page, element, problem, evidence screenshot, severity, fixed-in commit or "open").

- [ ] **Step 1: `make_fleet_db.py` with its test (TDD).** Hosts named `soak-NNNN`, labels `env` over prod/dr/dev and `site` dc0..dc4, machine ids `m-ui-NNNN`; each host gets `scans_per_host` bundles through `ingest_bundle` so drift is computed; the second bundle of every 10th host changes one finding title so the fleet page shows a non-zero drift chip. Runs in under 3 minutes for 500 hosts (use the same `Repo` the daemon uses; one `Repo` instance).
- [ ] **Step 2: Start the daemon on the DB** (`.venv/bin/pqcscan daemon --db <db> --port <free>` in the background, loopback, no token needed) and record its URL.
- [ ] **Step 3: Measure with Chrome DevTools MCP.** For `/fleet`, `/fleet?label=env=prod`, one host page `/fleet/<id>` and the fleet export trigger (`/api/scans/fleet/export/json`, time only): navigation timings via `performance_start_trace` → `performance_stop_trace` (TTFB, DOMContentLoaded, load, transfer size) and a `lighthouse_audit` (performance, accessibility, best-practices) per page; write `timings.json`; screenshots at 1440×900 and 390×844 with `take_screenshot`. F13 in FLEET-EVIDENCE ("the export works at fleet scale: nothing timed") gets numbers here: also time `GET /api/scans/fleet/export/json` and `/cbom` with curl (`-w %{time_total}`) at 500 hosts and record them.
- [ ] **Step 4: Design and accessibility review with the installed skills.** Invoke, in this order, each on the live pages (give them the URL and the screenshots): `interfaces:interface-review`, `interfaces:better-accessibility`, `impeccable:impeccable` (review mode, not a redesign), `taste-skill:taste-skill`, `ui-ux-pro-max:ui-ux-pro-max` (design-review). Collect every finding into `docs/FLEET-UI-REVIEW.md`: page, element, problem, evidence (screenshot name or Lighthouse audit id), severity (defect: broken, unreadable, inaccessible, misleading, or slow; or polish), and the skill that raised it. Defects get fixed in this task when the fix is a template/CSS/route change under 40 lines each and adds no feature; polish stays open with the skill's suggestion recorded. Re-screenshot after each fix; the review table cites the before and after images.
- [ ] **Step 5: Tests, lint, commit.** Existing UI tests (`tests/integration/test_ui_fleet.py`) must pass; ruff, mypy. Commit the tooling, screenshots (PNG, each under 400 KB; use 80 % quality JPEG if larger), timings, review doc and fixes in separate commits: `bench(ui): make_fleet_db and browser timings at 500 hosts`, `docs(ui): FLEET-UI-REVIEW with skill findings`, one `fix(ui): …` per defect.

### Task 12: The evidence summary as a designed, regenerable page

**Files:**
- Create: `benchmark/fleet/evidence_page.py`, `docs/evidence/index.html` (self-contained: inline CSS, no external scripts except fonts), `docs/evidence/README.md`
- Test: `tests/benchmark/test_evidence_page.py` (builds the page from the committed JSONs into tmp; asserts the item verdict table, the capacity numbers and the soak counts appear; no `<script src=` to anything but the allowed CDNs)

**Interfaces:**
- Consumes: `docs/FLEET-EVIDENCE.md` (the "Since PR #92" section, Task 10), `benchmark/fleet/results/*.json` (capacity sweep, herd, par, pginsert, ci-baseline, soak-real-*.json), `benchmark/fleet/profiles/*/summary.json`, `benchmark/fleet/mutation/score.json`, `benchmark/fleet/fuzz/stats.json`.
- Produces: `python -m benchmark.fleet.evidence_page` regenerates `docs/evidence/index.html` with: the six item verdicts, the capacity table with the measured bands per backend, the before/after top-three frames, the soak day counters per host, mutation score and fuzz CPU-hours/coverage, the findings list with status, and the tag decision; a dark/light theme via CSS tokens; readable at 390 px width; every number traceable to a named file (a "source" cell per row).

- [ ] **Step 1: Build the data loader and the page generator (TDD on the loader with synthetic JSONs).**
- [ ] **Step 2: Design pass with the skills:** `ui-ux-pro-max:design` for the layout and system, `taste-skill:taste-skill`, then `impeccable:impeccable` for the finish review; view the result in Chrome DevTools MCP at 1440 and 390 px; Lighthouse accessibility ≥ 95; fix what the skills and Lighthouse flag.
- [ ] **Step 3: Commit** `docs(evidence): regenerable evidence page under docs/evidence` with the screenshots in `benchmark/fleet/ui/evidence-*.png`. Task 10 links it from the top of FLEET-EVIDENCE.md.
