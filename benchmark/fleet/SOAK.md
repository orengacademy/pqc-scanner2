SIMULATED on one host — see soak-real.md for the real run

# Fleet soak, simulated

This is a simulation. Thirty "hosts" are thirty agent state directories on one Linux box. Each runs the real
`pqcscan agent --once` once per cycle against a real collector (`create_app` under uvicorn) on SQLite or on Postgres 16.
Cycles last two to three minutes instead of a day, seven cycles stand in for seven days, and four faults are injected.
It tests that the spool, enrolment, revoke, ingest, duplicate, drift and retention code behaves as `docs/FLEET.md`
says. It is not the real soak the campaign asks for. That one needs real Linux and Windows hosts and seven days; its
runbook is [`soak-real.md`](soak-real.md), and nothing in this file counts as having run it.

## Setup

| Item | Value |
|---|---|
| Box | 8 cores, 31 GB, Linux 7.0.0-38-generic, Python 3.11, Docker for Postgres. Shared with other work: load average 7 to 33 at cycle starts across all runs |
| Provenance | `soak.py` and the smoke test were untracked when runs 1 to 3 were made and were committed afterwards (`e5c43e0`). The run-3 JSONs say so in `provenance_note`; the harness hash is unknown for them. Later runs record `src_hash`, `harness_hash` and `dirty_files` with untracked files counted |
| Commits | Run 3 (the one tabled below): SQLite at `e4c753c`, Postgres at `9d086c3`, clean tree. Both include the ingest bulk-insert commit `05289fd` |
| Command | `python -m benchmark.fleet.soak --db sqlite --hosts 30 --cycles 7 --interval 60 --fault-plan default`, and the same with `--db postgres` |
| Results | `results/soak-simulated-<db>-20261017[-N].json`, one per run, with every per-host, per-cycle value, the collector log and the commands |
| Tables | `python -m benchmark.fleet.soak --render results/<file>.json` prints the two tables below from a result file |

**Each simulated host** has its own state dir (`agent.token`, `agent.db`, `spool/`), its own machine id
(`PQCSCAN_TEST_MACHINE_ID=m-soak-001` to `-030`), three labels (`group`, `site`, `env=soak`) and a fixture dir with one
self-signed RSA-1024 certificate. The agent is invoked with `--path <fixture dir> --allow-http`, so the cycle is the
product's own code from the subprocess start to the exit code.

**The collector** runs inside the harness process, one uvicorn worker like `pqcscan daemon`, with
`--keep-scans-per-host 3` so pruning shows up by cycle 4 (the default is 12). A pure-ASGI tap in front of the app
records the status and JSON of every `/api/ingest` and `/api/agents/enroll` call and attributes each to a machine
id from the enrol exchange. The tap does not change what the app does. The collector's loguru output is kept.

**Fault plan** (the cycle numbers are the brief's; "end of cycle" means after that cycle's agents have finished):

| Cycle | Fault |
|---|---|
| 2 | Collector stopped for the whole cycle |
| 3, end | `pqcscan agents revoke` on host 5 (a real CLI subprocess against the collector DB) |
| 4, start | Host 7's `--path` is changed to a dir holding a different certificate |
| 5, end | `pqcscan agents unrevoke` on host 5 |
| 6, end | Host 9's previous bundle is rebuilt from its agent DB with `dump_bundle` (same `scan_uuid`) and POSTed with its token |
| After 7 | Host 9's bundle is re-posted until the collector answers 429, to see whether duplicates cost a token |

## Where the simulation differs from the plan, and from a real fleet

- **A cycle is not 60 s.** `agent --once` always runs the host probes (dpkg, trust store, openssl, listening ports),
  whatever `--path` says. Each scan took 20 to 60 s of wall time under six at a time and stored about 1,670 findings.
  Thirty hosts could not finish in 60 s, so `--interval` is the minimum gap between cycle starts and every cycle
  started as soon as the last one ended. Cycles took 120 to 200 s.
- **One hostname.** The product has no test hook for the hostname (only `PQCSCAN_TEST_MACHINE_ID`), so all 30 hosts
  report the box's hostname and are told apart by machine id. `/fleet` sorts by hostname, so its order is not meaningful here.
- **Identical content.** All hosts share the box's host-level findings. Only the cert under `--path` differs. That is why
  zero drift is expected on every host but one, and why a drift row anywhere else needs an explanation.
- **Stopping the collector resets its in-memory rate-limit buckets.** After cycle 2 every host starts cycle 3 with a
  full burst of 10, so this run says nothing about throttling after an outage.
- **Load comes from the box, not the network.** Loopback, no TLS, no proxy, no clock skew, no Windows.

## Runs

Six runs were made. Runs 1 and 2 are kept because they show the two product bugs that run 3 no longer has.

| Run | DB | Commit | Load at cycle starts | Unexplained non-zeros | What happened |
|---|---|---|---|---|---|
| 1 | SQLite | `3d04413` | 9 to 14 | 0 | Clean apart from the duplicate-token finding |
| 1 | Postgres | `56d610f` | 10 to 14 | 1 | Host 14, cycle 3: drift 4 on the spooled bundle. The text of those rows was not captured |
| 2 | Postgres | `97c8578` | 7 to 22 | 7 | Drift 4 on seven (host, cycle) cells, every row `net.ports.tcp` |
| 2 | SQLite | `97c8578` | 14 to 33 | 12 | The same, 62 drift rows in all |
| 3 | SQLite | `e4c753c` | 12 to 23 | 0 | After the fixes below |
| 3 | Postgres | `9d086c3` | 11 to 21 | 0 | After the fixes below |

Run-1 JSONs have `tree_dirty: true`: unrelated files (`LOAD.md`, `run_load.py`, `benchmark/last_report.json`) were modified
in the shared checkout, and the harness did not count untracked files at all.

Run 2 changed the harness to store the text of every drifting ingest. The first run's JSON had a hard-coded
`final.stale: 0` field that measured nothing; it was removed from the two run-1 files and from the code. Nothing
else in any result file was edited.

A smoke run of the harness before run 1 found the first bug: every host showed drift 2 in cycle 2 with nothing
changed.

## Expected against observed, run 3

The expected column comes from the sentence of `docs/FLEET.md` quoted next to it. A "NO" is a disagreement between
the code and that sentence. The duplicate-resend row was re-evaluated after `docs/FLEET.md` was corrected to what the code does
(see Finding 3); at run time it recorded a miss against the old sentence.

**Ingest success rate: 210 of 211 (99.5%) on SQLite and on Postgres.** The one call that was not a 200 is the 401 that
revoked host 5 (`m-soak-005`) got in cycle 4, which is the injected fault. Without it the rate is 100%. The result
JSON has it as `ingest_success`.

### SQLite, run 3 (2026-10-17T15:47:53Z, commit e4c753c6c)

| fault | expected | FLEET.md sentence | observed | match |
|---|---|---|---|---|
| baseline, cycle 1 | 30 hosts enrol (201) and report (200), spool 0, exit 0 | The first run enrolls and stores a per-agent token (FLEET.md section 2) | enrolled 30, stored 30, spool 0, exit codes summed 0 | yes |
| collector down, cycle 2 | every host exits 0 with its bundle spooled (spool 1 each); no call reaches the collector | If the collector is down, the bundle is spooled under `<db dir>/agent/spool/` and sent on the next run. It exits 0 when the report was sent or spooled for retry (FLEET.md section 2, Deployment recipes) | outcomes {'reported': 0, 'spooled': 30, 'rejected': 0, 'crash': 0}, spool total 30, calls that reached the collector 0 | yes |
| spool drains, cycle 3 | spool back to 0 on every host; 60 bundles stored (the spooled one and the new one, per host) | ... and sent on the next run. (FLEET.md section 2) | spool total 0, stored 60, stored scans per host [3] | yes |
| revoke host 5 at the end of cycle 3; cycles 4 and 5 | cycle 4: host 5 ingest 401, re-enrol 403, bundle spooled, exit 0. Cycle 5: enrol 403, spool 2. Other hosts unaffected | A revoked host's ingest gets 401 and its re-enroll gets 403, so its bundles spool and replay after `agents unrevoke`. (FLEET.md Known limits) | cycle 4 host 5: 401 x1, enrol 403 x1, spool 1, exit 0. Cycle 5: enrol 403 x1, spool 2. Other hosts stored in cycle 4: 29 of 29 | yes |
| unrevoke host 5 at the end of cycle 5; cycle 6 | host 5 enrols (201), its 2 spooled bundles and the new one are stored (3), spool 0 | `pqcscan agents unrevoke <id>` lets it enroll again ... re-enrolls and sends (spooled bundles included). (FLEET.md section 6) | enrol 201 x1, stored 3, spool 0 | yes |
| host 7 scans a different cert dir from cycle 4 | drift > 0 in the ingest response and as fleet.drift rows in the stored scan; 0 the next cycle; 0 for every other host in every cycle | Each finding that appeared or vanished becomes one `fleet.drift` finding (severity info) in the new scan. The ingest response reports the number of changes as `drift`. (FLEET.md Drift between scans) | host 7 cycle 4: drift [6], drift rows in DB 6; cycle 5: [0]; drift rows from all other hosts and cycles: 0 | yes |
| replay host 9's previous bundle after cycle 6 | 200 with `duplicate: true`, 0 findings stored, no new scan | a duplicate bundle prunes nothing (FLEET.md Retention) | status 200, body {'scan_id': 126, 'stored_findings': 0, 'stored_views': 0, 'duplicate': True, 'drift': 0}, scans for the host 3 -> 3 | yes |
| does a duplicate resend spend an ingest token? | spent like any post: duplicates answered 200 with `duplicate: true`, at most 10 in a row, then 429 | Every post spends a token before the bundle is read, a duplicate resend included: it is answered `200` with `duplicate: true`, and after 10 in a row the next one gets `429`. (FLEET.md Security, Ingest limits) | ['200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '429']: 429 after 10 duplicates | yes |
| retention at --keep-scans-per-host 3 | scans pruned per cycle [0, 0, 0, 29, 29, 32, 30]; no host above 3 stored scans | After each stored bundle the daemon deletes that host's scans beyond the newest N ... Change the number with `pqcscan daemon --keep-scans-per-host N` (FLEET.md Retention) | pruned per cycle [0, 0, 0, 29, 29, 32, 30]; most scans on one host 3 | yes |
| 429 and 503 answers | no 429, no 503, no other ingest status in any cycle | Each host may post a burst of 10 bundles, refilled at one per minute (FLEET.md Security) | 429: 0, 503: 0, other: 0 | yes |
| rejected spool files | 0 files in spool/rejected on every host (nothing in this plan draws a 400, 403 or 413 on ingest) | A spooled file that gets one of these moves to `<state dir>/spool/rejected/` (FLEET.md Known limits) | files over all cycles and hosts: 0 | yes |
| labels | 3 labels on every host, constant (the cap is 64) | Labels merge across bundles. Host labels are capped at 64 per host (FLEET.md Security, Ingest limits) | min and max labels per host, by cycle: [(3, 3), (3, 3), (3, 3), (3, 3), (3, 3), (3, 3), (3, 3)] | yes |
| agent exit codes | every agent run exits 0 (reported or spooled) | `--once` (one cycle; exit 1 if the scan crashed or the collector permanently rejected the report, a spooled report exits 0) (FLEET.md Agent loop) | exit codes summed over all runs: 0 | yes |
| collector log | no WARNING or ERROR lines (a failed prune would log one) | If the trim itself fails the ingest still succeeds and a warning is logged. (FLEET.md Retention) | 0 warning lines, 31 info lines | yes |

| cycle | wall s | load | reported/spooled/other | stored (200) | dup | 401 | 429 | 503 | enrol 201/403 | spool total (max) | rejected | drift rows | pruned | scans stored | labels min-max | agent s p50/max | ingest ms p50/p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 121.6 | 15.9 | 30/0/0 | 30 | 0 | 0 | 0 | 0 | 30/0 | 0 (0) | 0 | 0 | 0 | 30 | 3-3 | 23.3/29.7 | 329/562 |
| 2 (collector down) | 153.7 | 12.8 | 0/30/0 | 0 | 0 | 0 | 0 | 0 | 0/0 | 30 (1) | 0 | 0 | 0 | 30 | 3-3 | 28.3/47.1 | 0/0 |
| 3 | 201.7 | 11.8 | 30/0/0 | 60 | 0 | 0 | 0 | 0 | 0/0 | 0 (0) | 0 | 0 | 0 | 90 | 3-3 | 39.1/53.6 | 1318/3625 |
| 4 | 147.1 | 19.9 | 29/1/0 | 29 | 0 | 1 | 0 | 0 | 0/1 | 1 (1) | 0 | 6 | 29 | 90 | 3-3 | 28.8/34.3 | 870/1847 |
| 5 | 167.3 | 16.8 | 29/1/0 | 29 | 0 | 0 | 0 | 0 | 0/1 | 2 (2) | 0 | 0 | 29 | 90 | 3-3 | 27.5/61.1 | 803/7852 |
| 6 | 149.0 | 23.0 | 30/0/0 | 32 | 0 | 0 | 0 | 0 | 1/0 | 0 (0) | 0 | 0 | 32 | 90 | 3-3 | 27.2/37.5 | 1075/3313 |
| 7 | 140.8 | 13.5 | 30/0/0 | 30 | 0 | 0 | 0 | 0 | 0/0 | 0 (0) | 0 | 0 | 30 | 90 | 3-3 | 26.5/37.2 | 746/2383 |

### Postgres, run 3 (2026-10-17T16:06:03Z, commit 9d086c387)

| fault | expected | FLEET.md sentence | observed | match |
|---|---|---|---|---|
| baseline, cycle 1 | 30 hosts enrol (201) and report (200), spool 0, exit 0 | The first run enrolls and stores a per-agent token (FLEET.md section 2) | enrolled 30, stored 30, spool 0, exit codes summed 0 | yes |
| collector down, cycle 2 | every host exits 0 with its bundle spooled (spool 1 each); no call reaches the collector | If the collector is down, the bundle is spooled under `<db dir>/agent/spool/` and sent on the next run. It exits 0 when the report was sent or spooled for retry (FLEET.md section 2, Deployment recipes) | outcomes {'reported': 0, 'spooled': 30, 'rejected': 0, 'crash': 0}, spool total 30, calls that reached the collector 0 | yes |
| spool drains, cycle 3 | spool back to 0 on every host; 60 bundles stored (the spooled one and the new one, per host) | ... and sent on the next run. (FLEET.md section 2) | spool total 0, stored 60, stored scans per host [3] | yes |
| revoke host 5 at the end of cycle 3; cycles 4 and 5 | cycle 4: host 5 ingest 401, re-enrol 403, bundle spooled, exit 0. Cycle 5: enrol 403, spool 2. Other hosts unaffected | A revoked host's ingest gets 401 and its re-enroll gets 403, so its bundles spool and replay after `agents unrevoke`. (FLEET.md Known limits) | cycle 4 host 5: 401 x1, enrol 403 x1, spool 1, exit 0. Cycle 5: enrol 403 x1, spool 2. Other hosts stored in cycle 4: 29 of 29 | yes |
| unrevoke host 5 at the end of cycle 5; cycle 6 | host 5 enrols (201), its 2 spooled bundles and the new one are stored (3), spool 0 | `pqcscan agents unrevoke <id>` lets it enroll again ... re-enrolls and sends (spooled bundles included). (FLEET.md section 6) | enrol 201 x1, stored 3, spool 0 | yes |
| host 7 scans a different cert dir from cycle 4 | drift > 0 in the ingest response and as fleet.drift rows in the stored scan; 0 the next cycle; 0 for every other host in every cycle | Each finding that appeared or vanished becomes one `fleet.drift` finding (severity info) in the new scan. The ingest response reports the number of changes as `drift`. (FLEET.md Drift between scans) | host 7 cycle 4: drift [6], drift rows in DB 6; cycle 5: [0]; drift rows from all other hosts and cycles: 0 | yes |
| replay host 9's previous bundle after cycle 6 | 200 with `duplicate: true`, 0 findings stored, no new scan | a duplicate bundle prunes nothing (FLEET.md Retention) | status 200, body {'scan_id': 127, 'stored_findings': 0, 'stored_views': 0, 'duplicate': True, 'drift': 0}, scans for the host 3 -> 3 | yes |
| does a duplicate resend spend an ingest token? | spent like any post: duplicates answered 200 with `duplicate: true`, at most 10 in a row, then 429 | Every post spends a token before the bundle is read, a duplicate resend included: it is answered `200` with `duplicate: true`, and after 10 in a row the next one gets `429`. (FLEET.md Security, Ingest limits) | ['200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '200/dup', '429']: 429 after 10 duplicates | yes |
| retention at --keep-scans-per-host 3 | scans pruned per cycle [0, 0, 0, 29, 29, 32, 30]; no host above 3 stored scans | After each stored bundle the daemon deletes that host's scans beyond the newest N ... Change the number with `pqcscan daemon --keep-scans-per-host N` (FLEET.md Retention) | pruned per cycle [0, 0, 0, 29, 29, 32, 30]; most scans on one host 3 | yes |
| 429 and 503 answers | no 429, no 503, no other ingest status in any cycle | Each host may post a burst of 10 bundles, refilled at one per minute (FLEET.md Security) | 429: 0, 503: 0, other: 0 | yes |
| rejected spool files | 0 files in spool/rejected on every host (nothing in this plan draws a 400, 403 or 413 on ingest) | A spooled file that gets one of these moves to `<state dir>/spool/rejected/` (FLEET.md Known limits) | files over all cycles and hosts: 0 | yes |
| labels | 3 labels on every host, constant (the cap is 64) | Labels merge across bundles. Host labels are capped at 64 per host (FLEET.md Security, Ingest limits) | min and max labels per host, by cycle: [(3, 3), (3, 3), (3, 3), (3, 3), (3, 3), (3, 3), (3, 3)] | yes |
| agent exit codes | every agent run exits 0 (reported or spooled) | `--once` (one cycle; exit 1 if the scan crashed or the collector permanently rejected the report, a spooled report exits 0) (FLEET.md Agent loop) | exit codes summed over all runs: 0 | yes |
| collector log | no WARNING or ERROR lines (a failed prune would log one) | If the trim itself fails the ingest still succeeds and a warning is logged. (FLEET.md Retention) | 0 warning lines, 31 info lines | yes |

| cycle | wall s | load | reported/spooled/other | stored (200) | dup | 401 | 429 | 503 | enrol 201/403 | spool total (max) | rejected | drift rows | pruned | scans stored | labels min-max | agent s p50/max | ingest ms p50/p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 128.8 | 12.4 | 30/0/0 | 30 | 0 | 0 | 0 | 0 | 30/0 | 0 (0) | 0 | 0 | 0 | 30 | 3-3 | 24.5/31.0 | 3075/6018 |
| 2 (collector down) | 139.1 | 11.1 | 0/30/0 | 0 | 0 | 0 | 0 | 0 | 0/0 | 30 (1) | 0 | 0 | 0 | 30 | 3-3 | 25.1/37.7 | 0/0 |
| 3 | 167.4 | 15.0 | 30/0/0 | 60 | 0 | 0 | 0 | 0 | 0/0 | 0 (0) | 0 | 0 | 0 | 90 | 3-3 | 31.9/39.1 | 3971/9126 |
| 4 | 182.0 | 12.0 | 29/1/0 | 29 | 0 | 1 | 0 | 0 | 0/1 | 1 (1) | 0 | 6 | 29 | 90 | 3-3 | 34.1/43.1 | 4649/8830 |
| 5 | 151.7 | 21.0 | 29/1/0 | 29 | 0 | 0 | 0 | 0 | 0/1 | 2 (2) | 0 | 0 | 29 | 90 | 3-3 | 29.5/40.7 | 3590/9781 |
| 6 | 164.9 | 12.2 | 30/0/0 | 32 | 0 | 0 | 0 | 0 | 1/0 | 0 (0) | 0 | 0 | 32 | 90 | 3-3 | 31.3/47.1 | 4569/10578 |
| 7 | 134.0 | 13.5 | 30/0/0 | 30 | 0 | 0 | 0 | 0 | 0/0 | 0 (0) | 0 | 0 | 30 | 90 | 3-3 | 25.7/33.2 | 4078/8180 |

## Findings

Every number above zero that `docs/FLEET.md` does not predict, and every sentence that did not hold.

1. **Fixed, product bug: the system clock finding made every host drift on every scan.** `aux.clock.cert_validity`
   put the scan's timestamp in its title, so each scan produced two `fleet.drift` rows (old clock removed, new clock
   added), and `/fleet` would show a drift chip on every host after its second scan. FLEET.md predicts drift only for
   findings that "appeared or vanished". Seen as drift 2 on every host in the smoke run's second cycle. Fixed in
   `91372e4` (the title is fixed, the time stays in `evidence.utc_now`), with a test and a CHANGELOG line.
2. **Fixed, product bug: `net.ports.tcp` lost open ports when the box was busy, and fleet drift reported it.** The
   probe timed each connect with an in-loop `wait_for` (0.4 s). Anything that blocks the loop for more than
   0.4 s expires that timer, so a port that accepted at once could still read as closed. The scan's other probes write
   to the database synchronously on that loop, which is the likely stall; no loop-lag measurement was made, and the fix
   does not depend on which stall it is. On this box four well-known
   ports are open, so the effect was exactly four drift rows (`removed net.ports.tcp`), and four `added` on the next
   scan. Runs 2 on both databases: 19 such cells at box load 7 to 33, always four rows, and wherever the same host had
   a later scan, that scan reversed the change. Run 1 SQLite (load 9 to 14) had none, run 1 Postgres had one cell whose text was not
   captured. Reproduced outside the harness with the command below: of 12 concurrent local scans, 2 found none of the four ports
   and 10 found all four; after the fix 12 of 12 found all four. Fixed in `e4c753c` (the connect runs in a thread with the socket's
   own timeout), with a deterministic test that blocks the loop for a second. Runs 3, after both fixes, had 6 drift rows
   in each database, all from host 7's injected change. Caveat: that is one run per database after the fix, on a box
   whose load changes by the minute. Other probes that time a connect inside the loop (`grep open_connection
   src/pqcscan/probes` finds 29 uses) were not checked for the same weakness.
   ```bash
   # 12 full host scans at once on a loaded box; the number of open well-known ports (4 here) should be the same in every DB
   mkdir -p /tmp/ports/empty
   for i in $(seq 1 12); do pqcscan scan --db /tmp/ports/r$i.db --path /tmp/ports/empty --fail-on none >/dev/null 2>&1 & done; wait
   for f in /tmp/ports/r*.db; do python -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(\"select count(*) from findings where probe_id='net.ports.tcp'\").fetchone()[0])" $f; done | sort | uniq -c
   ```
   Before the fix this printed `2 0` and `10 4`; after it, `12 4`. The counts depend on the box and its load, so a
   single run proves little. Run it a few times, and on an idle box expect all 4.
3. **Fixed, documentation: "only a duplicate resend is free" was wrong.** `docs/FLEET.md` (Security, Ingest limits)
   said so. Re-posting an already stored bundle returned `200` with `duplicate: true` ten times and then `429`, on both
   databases, so a duplicate spends a token like any other bundle. The comment in `daemon/fleet.py` says that is on
   purpose ("Every outcome spends the token, duplicates included"). `docs/FLEET.md` now says the same: every post spends a token,
   a duplicate is answered `200` with `duplicate: true`, and after 10 in a row the next gets `429`.
4. **Observation, not in FLEET.md: ingest latency at real bundle size.** A real scan stores about 1,670 findings, not the
   300 of the load test. With six agents posting at once, the collector's own ingest time per call was
   0.3 to 1.3 s (p50) and 0.6 to 7.9 s (p95) on SQLite, and 3.1 to 4.6 s (p50) and 6.0 to 10.6 s (p95) on Postgres,
   by cycle. No call timed out (the agent waits 60 s), none drew a 429 or 503, and no bundle was stored twice by a
   retry. Postgres was several times slower than SQLite per call here, in line with `LOAD.md`. FLEET.md's advice to move
   to Postgres past about 10,000 hosts a day is about write concurrency, not latency, and this does not contradict it.
5. **Observation, not in FLEET.md: database size.** The SQLite file was 106 MB with 90 stored scans (30 hosts at 3
   each), about 1.2 MB per scan. A straight-line extrapolation to the default 12 scans per host is 420 MB for 30
   hosts and about 28 GB for 2,000. That is arithmetic on one measurement, not a test.

Nothing else was above zero. All 14 run-3 checks per database match (the duplicate row after the FLEET.md correction). All three runs of each
database showed the same fault behaviour: no 429, no 503, no rejected spool file, every agent exit code 0, three
labels on every host in every cycle, no collector log line above INFO.

## What this does not show

- Anything about real networks, TLS, proxies, DNS or Windows. The Windows installer is the Pester job's business, not this file's.
- Seven days of wall time: no token-bucket refill over a day, no `last_seen` staleness (48 h), no clock changes.
- Different hosts. Thirty copies of one box's findings cannot show drift that real fleets have, or label churn.
- A collector that survives the outage with its state. The harness restarts it, which also empties its rate limiter.
- The IBM i export path and the packaging recipes. The runbook covers them.

## Re-running

```bash
pip install -e '.[dev]' 'psycopg[binary]'
python -m benchmark.fleet.soak --db sqlite   --hosts 30 --cycles 7 --interval 60 --fault-plan default
python -m benchmark.fleet.soak --db postgres --hosts 30 --cycles 7 --interval 60 --fault-plan default
pytest tests/benchmark/test_fleet_soak_smoke.py        # 3 hosts, 2 cycles, no faults, about 40 s
```

Each run takes 15 to 20 minutes. The exit status is 0 only if every expected-versus-observed row matches. A result file is never overwritten; reruns get `-2`, `-3`.
