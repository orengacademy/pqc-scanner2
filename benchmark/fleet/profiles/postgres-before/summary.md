# Profile: postgres 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `c330937af`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 361 s, ingest p50 60000.0 ms, p95 60000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `_communicate_gen (psycopg/_pipeline_base.py:112)` | 28.1 | 28.1 |
| `wait (psycopg/connection.py:495)` | 24.5 | 66.4 |
| `_collect_insert_commands (sqlalchemy/orm/persistence.py:349)` | 3.1 | 3.1 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 10.4 % of samples.

Statements per ingest: **16996.1** (total statements over the run divided by the 270 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: pg_stat_statements).

Slow event-loop callbacks (>= 100 ms): 0, max 0.000 s.
