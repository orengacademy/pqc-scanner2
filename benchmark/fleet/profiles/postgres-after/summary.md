# Profile: postgres 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `58f22a25a`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 352 s, ingest p50 1900.0 ms, p95 60000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `wait (psycopg/connection.py:495)` | 28.8 | 62.3 |
| `_communicate_gen (psycopg/_pipeline_base.py:112)` | 19.9 | 19.9 |
| `run (asyncio/runners.py:118)` | 3.8 | 8.0 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 19.5 % of samples.

Statements per ingest: **16131.4** (total statements over the run divided by the 147 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: pg_stat_statements).

Slow event-loop callbacks (>= 100 ms): 285, max 0.747 s.
