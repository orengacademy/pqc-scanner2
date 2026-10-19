# Profile: sqlite 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `58f22a25a`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 320 s, ingest p50 2600.0 ms, p95 44000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `do_execute (sqlalchemy/engine/default.py:1192)` | 24.8 | 24.8 |
| `raw_decode (json/decoder.py:353)` | 4.7 | 4.8 |
| `fetchall (sqlalchemy/engine/cursor.py:1315)` | 4.2 | 4.2 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 18.8 % of samples.

Statements per ingest: **34.8** (total statements over the run divided by the 403 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: sqlite3 trace callback).

Slow event-loop callbacks (>= 100 ms): 273, max 0.964 s.
