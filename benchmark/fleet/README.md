# Fleet collector load test

Posts real bundles from simulated agent hosts at the fleet collector (`pqcscan daemon`) and reports ingest
latency, errors, and the collector's own throttling answers. Results live in [`LOAD.md`](LOAD.md) (one row per run)
and `results/load-<db>-<YYYYMMDD>[-<hosts>h][-herd][-N].json` (full record with the exact commands and the git commit; the plain name is the 500-host staggered run, `N` numbers reruns, files are never overwritten; `*-prefix.json` ran before commit 41b9dea).

Related: [`SOAK.md`](SOAK.md) is the simulated 30-host, 7-cycle soak with its faults and findings, and
[`soak-real.md`](soak-real.md) is the runbook for the real one.

## Run it

```bash
pip install -e '.[dev]' locust 'psycopg[binary]'     # locust and psycopg are not runtime dependencies
python -m benchmark.fleet.run_load --db sqlite   --hosts 500 --spawn-rate 50 --duration 120s --findings-per-bundle 300
python -m benchmark.fleet.run_load --db postgres --hosts 500 --spawn-rate 50 --duration 120s --findings-per-bundle 300
python -m benchmark.fleet.run_load --db sqlite --herd ...    # every host posts the moment it spawns
```

Each run starts its own collector on a free loopback port (SQLite file in a temp dir, or a throwaway
`postgres:16-alpine` container started with `docker run` and killed in a `finally`), builds one template scan,
runs locust headless in a subprocess, parses its CSV, then writes the JSON and appends the `LOAD.md` row.
Exit status is 0 only when ingest p95 is under 2 s and there were no errors.

Smoke test (5 hosts, 10 s, SQLite, marker `benchmark`): `pytest tests/benchmark/test_fleet_load_smoke.py`.

## What one simulated host does

1. `POST /api/agents/enroll` once, with a machine id `m-load-NNNN`, hostname, and labels (after the offset below).
2. Staggered (the default): waits a random offset in `[0, 60 s)` (seeded by `--seed`, recorded in the JSON) before
   enrolling, as an agent does on its first scan. `--herd`: enrols and posts at once; with 500 hosts at 50 spawns/s
   that is a 10 s ramp, not a single instant.
3. `POST /api/ingest` with a gzip bundle and a fresh `scan_uuid`, then once more every 60 s. The collector's
   per-host token bucket refills one token a minute (burst 10), so a host that posts once a minute is never throttled.

Staggered arrival offers a steady `hosts / 60` bundles per second. The herd offers all hosts at once and is the
literal reading of "500 hosts posting concurrently". Both are reported.

## What it measures, and what it does not

- **Ingest percentiles** come from locust's `ingest` row only, not the enrolment calls. Requests time out after 60 s,
  the real agent's HTTP timeout; a timeout is an error. After the run locust waits up to 70 s for in-flight requests
  so a backlog is counted instead of discarded.
- **Queueing.** The collector parses and stores at most `INGEST_PARALLELISM=2` bundles at once and holds that slot
  across both steps, so at overload the p50 and p95 are mostly queue wait, not service time. The server also keeps
  working on a request after the client gave up at 60 s, so an overloaded run wastes capacity on bundles nobody is
  waiting for. `stored_scans` in the JSON (counted through `/api/fleet` after the run) shows how many arrived.
- **429 and 503** are counted separately and are not errors: 429 is the per-host throttle working, 503 is the store
  reporting it is busy (the agent would spool and retry). Their latency is still inside the ingest percentiles.
- **Every host sends the same findings.** One template scan (`--findings-per-bundle`, default 300, about 40% weak
  rows with 8 compliance views each, the rest SBOM info rows with one) is stored through the real `Repo` and exported by
  the real `dump_bundle`; hosts differ only in identity and `scan_uuid`. The test therefore measures ingest cost per
  bundle, not content diversity, and it does not exercise drift between differing scans.
- **One box.** Locust and the collector share the machine, so the numbers include CPU contention between them and
  are not a network result. The `LOAD.md` rows record the box's 1-minute load average at start and end. A shared
  or busy box inflates latency, so compare rows only at similar load.
- **Single uvicorn worker**, as `pqcscan daemon` runs it.

## Postgres status

The Postgres path is wired and was run locally, against a `postgres:16-alpine` container on the same box. It is
untested in CI until the CI job from the evidence plan (Task 7) lands, and `docs/FLEET.md` should keep calling it
untested until then.

## Results (2026-10-17)

`LOAD.md` has every run, the summary, and the commit and box load of each row. Ingest p50 / p95, 300-finding bundles,
staggered arrival, from a clean worktree at commit 97c8578 (after the ingest bulk insert). Two seeds where run; the
second seed ran on a busier box, yet on SQLite it was faster at 90 and 250 hosts.

| hosts (bundles/s offered) | SQLite seed 1 | SQLite seed 2 | Postgres seed 1 | Postgres seed 2 |
|---|---|---|---|---|
| 30 (0.5) | 120 ms / 1.1 s | | 370 ms / 940 ms | |
| 60 (1) | 83 ms / 270 ms | 180 ms / 620 ms | 380 ms / 830 ms | 680 ms / 4.9 s |
| 90 (1.5) | 180 ms / 3.9 s | 190 ms / 760 ms | 600 ms / 3.4 s | 880 ms / 2.4 s |
| 120 (2) | 130 ms / 420 ms | 210 ms / 1.8 s | 570 ms / 1.7 s | 1.3 s / 5.7 s |
| 250 (4.2) | 290 ms / 11 s | 280 ms / 1.7 s | 30 s / 38 s | 57 s / 60 s |
| 500 (8.3) | 5.0 s / 8.6 s | | 60 s / 60 s | |
| 500, herd | 16 s / 32 s | | 60 s / 61 s | |

The 500-host target is not met. Capacity at p95 under 2 s is a band: SQLite passed at 120 hosts in both seeds but at
90 and 250 in only one, so it lies between 60 and 250; Postgres passed at 30 and in one of two seeds at 60 and 120, so
treat it as 30 to 60. The rows are not monotone in host count and box load was 10 to 31, so do not read a threshold
from them. `rps` counts every completed request, timeouts included.

Probable cause of the old ceiling: a 300-finding ingest used to issue about 1,450 SQL statements (one ORM flush per
finding, from a cProfile of one SQLite ingest). It now issues 10 statements on both SQLite and Postgres (two executemany inserts and one id
query), at about a tenth of the CPU. Postgres was re-measured on that code and is not measurably faster than with
RETURNING (see LOAD.md). Why Postgres still trails SQLite was not profiled.

Enrolment under load: before commit 41b9dea an enrolment waiting on SQLite's write lock blocked the whole event loop
(enroll p95 22 s at 500 hosts) and a lock timeout escaped as a 500. After it, enroll p95 is about 2 s and a busy store
answers 503.
