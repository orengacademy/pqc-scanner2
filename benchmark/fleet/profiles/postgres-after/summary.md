# Profile: postgres 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `0881a0db8`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 352 s, ingest p50 21000.0 ms, p95 60000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `_split_query (psycopg/_queries.py:433)` | 8.5 | 8.6 |
| `_split_query (psycopg/_queries.py:385)` | 7.7 | 7.8 |
| `wait (psycopg/connection.py:495)` | 7.2 | 65.1 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 12.9 % of samples.

Statements per ingest: **8100.8** (total statements over the run divided by the 176 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: pg_stat_statements).

Slow event-loop callbacks (>= 100 ms): 0, max 0.000 s.
