# Profile: sqlite 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `2a258070f`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 315 s, ingest p50 2700.0 ms, p95 41000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `do_execute (sqlalchemy/engine/default.py:1192)` | 23.4 | 23.4 |
| `raw_decode (json/decoder.py:353)` | 4.9 | 5.0 |
| `fetchall (sqlalchemy/engine/cursor.py:1315)` | 4.5 | 4.5 |

Before: `do_execute (sqlalchemy/engine/default.py:1192)` 17.3% (profiles/sqlite-before)

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 18.9 % of samples.

Statements per ingest: **34.3** (total statements over the run divided by the 420 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: sqlite3 trace callback).

Slow event-loop callbacks (>= 100 ms): 0, max 0.000 s.
