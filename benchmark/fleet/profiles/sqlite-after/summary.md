# Profile: sqlite 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `0881a0db8`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 316 s, ingest p50 2600.0 ms, p95 35000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `do_execute (sqlalchemy/engine/default.py:1192)` | 26.1 | 26.1 |
| `fetchall (sqlalchemy/engine/cursor.py:1315)` | 5.6 | 5.6 |
| `raw_decode (json/decoder.py:353)` | 5.2 | 5.2 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 13.9 % of samples.

Statements per ingest: **32.0** (total statements over the run divided by the 527 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: sqlite3 trace callback).

Slow event-loop callbacks (>= 100 ms): 0, max 0.000 s.
