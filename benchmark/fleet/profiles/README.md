# Load-run profiles

`python -m benchmark.fleet.run_load ... --profile DIR` records a profile of the collector while locust drives it.
The collector runs inside the harness process (uvicorn in a thread), so one py-spy recording of that process covers
it. Each directory here is one run.

| file | what it is |
|---|---|
| `pyspy.collapsed.txt` | py-spy samples (100 Hz, all threads, idle excluded) as collapsed stacks, `frame;frame;... count`. One recording per run: two py-spy processes cannot attach to one pid at once. |
| `asyncio-slow.log` | asyncio's `Executing <...> took N seconds` warnings: event-loop callbacks that held the loop for 100 ms or more (debug mode). Empty means none. |
| `statements.json` | Statements the database ran over the run. SQLite: every statement the sqlite3 trace callback saw, `BEGIN`/`COMMIT` included. Postgres: `pg_stat_statements` (`track=all`). The top 25 by count (SQLite) or total time (Postgres). |
| `auto_explain.log.gz` | Postgres only: the container log with `EXPLAIN ANALYZE` plans (buffers on) for a 2 % sample of statements, without parameter values. Sampling keeps the plan logging from distorting the profile. |
| `summary.json` | The run's key numbers, the top ten frames by self share, the instrumentation share, slow-callback count, statements per ingest. |
| `summary.md` | The same, short: the top three frames, the instrumentation share, statements per ingest, slow callbacks. |

Frame shares are of all samples. Samples inside the harness's own instrumentation are left out of the ranking and
reported as `instrumentation_pct`, so harness overhead never ranks as a product cost. That covers the SQLite
statement counter (`_count`) and the source tracebacks asyncio debug mode captures for every callback
(`traceback.extract`/`extract_stack`), which is the price of the slow-callback log.

Statements per ingest is the run's total statements divided by the scans the collector reports stored after the
run. Enrolments and the harness's post-run `/api/fleet` reads are in the total, so it slightly overstates the
per-bundle figure. The two backends count differently, so the figures are not comparable across them. SQLite counts
every statement the sqlite3 trace callback sees, which is one per `executemany` row. Postgres counts
`pg_stat_statements` calls, where a batched insert is one call, and the total includes schema creation.

The uvicorn loop is uvloop, whose loop and callback dispatch are compiled. Time spent there shows as self time
on `run (asyncio/runners.py:...)`, the last Python frame above it, not as separate frames.

## Open the flame graph

Go to <https://www.speedscope.app> and drag `pyspy.collapsed.txt` onto the page; speedscope reads collapsed-stack
files directly. "Left Heavy" groups identical stacks, "Sandwich" lists frames by self time.

## Permissions

py-spy attaches with ptrace, which `kernel.yama.ptrace_scope` 1 or higher reserves for root. As root (the load
droplet) it just runs. As another user the harness runs only the py-spy child under `sudo -n`, so it needs
passwordless sudo; without it the run fails before locust starts. It never writes an empty profile.
Postgres profiles also need Docker, as every Postgres run does.

## A before/after pair

Run the same arguments at the two commits, changing only the directory and the tag:

```bash
git checkout <before-commit>
python -m benchmark.fleet.run_load --db sqlite --hosts 500 --rate 4 --duration 300s \
    --profile benchmark/fleet/profiles/sqlite-before --tag before
git checkout <after-commit>
python -m benchmark.fleet.run_load --db sqlite --hosts 500 --rate 4 --duration 300s \
    --profile benchmark/fleet/profiles/sqlite-after --tag after
```

Use `--db postgres` with `postgres-before`/`postgres-after` for the Postgres pair. Add `--no-record` for a dry run
that writes neither a result file nor a `LOAD.md` row.
