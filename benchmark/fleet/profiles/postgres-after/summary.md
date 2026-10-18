# Profile: postgres 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `2a258070f`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 318 s, ingest p50 45000.0 ms, p95 60000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `wait (psycopg/connection.py:495)` | 35.7 | 74.0 |
| `_communicate_gen (psycopg/_pipeline_base.py:112)` | 28.8 | 28.8 |
| `_exec_command (psycopg/_connection_base.py:478)` | 1.7 | 1.7 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 17.6 % of samples.

Statements per ingest: **19411.3** (total statements over the run divided by the 89 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: pg_stat_statements).

Slow event-loop callbacks (>= 100 ms): 0, max 0.000 s.
