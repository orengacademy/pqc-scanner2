# Profile: postgres 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `04c2650dd`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 338 s, ingest p50 230.0 ms, p95 48000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `wait (psycopg/connection.py:495)` | 28.1 | 68.8 |
| `_communicate_gen (psycopg/_pipeline_base.py:112)` | 26.8 | 26.8 |
| `run (asyncio/runners.py:118)` | 3.2 | 5.3 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 12.7 % of samples.

Statements per ingest: **16102.6** (total statements over the run divided by the 235 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: pg_stat_statements).

Slow event-loop callbacks (>= 100 ms): 0, max 0.000 s.
