# Profile: sqlite 500 hosts at 4.0 posts/s, 1670 findings per bundle

Commit `c330937af`, box {'cpus': 8, 'cpu_model': 'DO-Regular', 'mem_gb': 16}, wall 361 s, ingest p50 60000.0 ms, p95 60000.0 ms.

## Top three costs (share of sampled wall time, self)

| frame | self % | total % |
|---|---|---|
| `do_execute (sqlalchemy/engine/default.py:1192)` | 17.3 | 17.3 |
| `do_executemany (sqlalchemy/engine/default.py:1189)` | 17.2 | 17.2 |
| `_collect_insert_commands (sqlalchemy/orm/persistence.py:349)` | 4.5 | 4.5 |

Harness instrumentation (statement counter, asyncio debug tracebacks), left out of the table: 20.2 % of samples.

Statements per ingest: **8528.2** (total statements over the run divided by the 301 scans the collector reports stored; enrolments (500) and the post-run fleet reads are included; source: sqlite3 trace callback).

Slow event-loop callbacks (>= 100 ms): not captured (empty log: harnesses before 74af188 lost the handler to uvicorn's logging config).
