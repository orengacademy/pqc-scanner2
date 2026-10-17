# Fleet collector load test

Posts real bundles from simulated agent hosts at the fleet collector (`pqcscan daemon`) and reports ingest
latency, errors, and the collector's own throttling answers. Results live in [`LOAD.md`](LOAD.md) (one row per run)
and `results/load-<db>-<YYYYMMDD>[-<hosts>h][-herd][-N].json` (full record with the exact commands and the git commit; the plain name is the 500-host staggered run, `N` numbers reruns, files are never overwritten; `*-prefix.json` ran before commit 41b9dea).

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

1. `POST /api/agents/enroll` once, with a machine id `m-load-NNNN`, hostname, and labels.
2. Waits a random offset in `[0, 60 s)` (staggered, the default) or posts immediately (`--herd`).
3. `POST /api/ingest` with a gzip bundle and a fresh `scan_uuid`, then once more every 60 s. The collector's
   per-host token bucket refills one token a minute (burst 10), so a host that posts once a minute is never throttled.

Staggered arrival offers a steady `hosts / 60` bundles per second. The herd offers all hosts at once and is the
literal reading of "500 hosts posting concurrently". Both are reported.

## What it measures, and what it does not

- **Ingest percentiles** come from locust's `ingest` row only, not the enrolment calls. Requests time out after 60 s,
  the real agent's HTTP timeout; a timeout is an error. After the run locust waits up to 70 s for in-flight requests
  so a backlog is counted instead of discarded.
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

## Results (2026-10-17, commit in each row of `LOAD.md`)

Ingest p95 against the 2 s target, 300-finding bundles, staggered arrival, box load average 5 to 13 during these rows.

| hosts (bundles/s offered) | SQLite p50 / p95 | Postgres p50 / p95 |
|---|---|---|
| 30 (0.5) | 0.36 s / 3.3 s | 1.1 s / 1.6 s |
| 60 (1) | 0.39 s / 1.8 s | 1.7 s / 10 s |
| 90 (1.5) | 0.46 s / 2.1 s | 2.6 s / 11 s |
| 120 (2) | 2.7 s / 14 s | 18 s / 28 s |
| 500 (8.3), staggered or herd | requests time out after 60 s | requests time out after 60 s |

The 500-host target is not met on either database. Completed bundles per second stay near 2 on SQLite (120 hosts:
236 bundles in 120 s) and near 1.4 on Postgres. Past that the queue grows and clients give up at 60 s; the 3 requests
per second in the 500-host rows are mostly those timeouts, since `rps` counts every completed request.

Probable cause, from a cProfile of one SQLite `ingest_bundle` with 300 findings: about 1,450 SQL statements and 300
ORM flushes (one per finding, to obtain its id for the views), most of the CPU time. That points at work inside one
process, not at the database lock. Postgres being slower is then a statement round-trip cost (a hypothesis; not
profiled). Making ingest cheaper is a product change and out of scope for this task. The p95 near the 2 s line is
noisy with 60 to 180 requests per run. Treat the 30 to 90 host rows as "around the limit", not as exact capacity.
`FLEET.md`'s "SQLite handles roughly 2,000 hosts daily" is consistent with this (2,000 bundles a day is 0.02 a second).

Enrolment under load: before commit 41b9dea an enrolment waiting on SQLite's write lock blocked the whole event loop
(enroll p95 22 s at 500 hosts) and a lock timeout escaped as a 500. After it, enroll p95 is 2.1 s (SQLite) and 1.6 s
(Postgres) at 500 staggered hosts, and a busy store answers 503.
