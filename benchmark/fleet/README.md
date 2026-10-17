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

`LOAD.md` has every run and the summary; commit and box load are in each row. Ingest p95, 300-finding bundles,
staggered arrival, after the ingest bulk insert (commit 05289fd). Before it, 500 hosts timed out on both databases and
the 2 s line was crossed between 60 and 90 hosts on SQLite and 30 and 60 on Postgres.

| hosts (bundles/s offered) | SQLite p50 / p95 | Postgres p50 / p95 |
|---|---|---|
| 30 (0.5) | 75 ms / 260 ms | 300 ms / 870 ms |
| 60 (1) | 67 ms / 1.4 s | 510 ms / 2.3 s |
| 90 (1.5) | 65 ms / 210 ms | 340 ms / 690 ms |
| 120 (2) | 81 ms / 2.9 s | 390 ms / 2.7 s |
| 250 (4.2) | 100 ms / 540 ms | 1.2 s / 8.9 s |
| 500 (8.3) | 2.0 s / 8.7 s | 50 s / 60 s, 307 timeouts |
| 500, herd | 12 s / 44 s | 53 s / 60 s, 254 timeouts |

The 500-host target is not met. Capacity at p95 under 2 s is about 250 hosts on SQLite and about 90 on Postgres,
each posting once a minute. Rows near the line are noisy, so read the 60 to 250 host rows as a band, not a threshold.
`rps` counts every completed request, timeouts included.

Probable cause of the old ceiling: a 300-finding ingest used to issue about 1,450 SQL statements (one ORM flush per finding, cProfile of
one SQLite ingest). It now issues 308 on SQLite (one cheap insert per finding, kept so ids stay in order) and 9 on
Postgres, at about a tenth of the CPU. Why Postgres still trails SQLite was not profiled.

Enrolment under load: before commit 41b9dea an enrolment waiting on SQLite's write lock blocked the whole event loop
(enroll p95 22 s at 500 hosts) and a lock timeout escaped as a 500. After it, enroll p95 is about 2 s and a busy store
answers 503.
