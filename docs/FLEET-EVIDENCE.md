# Fleet mode evidence: what is proven, simulated, asserted

Branch `verify/fleet-evidence`, written at `cd8f8d6`, 2026-10-18. This page grades every behaviour claim in [FLEET.md](FLEET.md)
against the artefacts the verification campaign produced. Every number below comes from a file named next to it.
Spec: `docs/superpowers/specs/2026-10-17-fleet-evidence-spec.md`.

**Verdict. Do not tag a release.** The spec holds the tag until items 1 to 4 pass. Item 3 fails and item 1 was only simulated.

| # | Spec item | Result | Basis |
|---|---|---|---|
| 1 | Real-fleet soak, 30 hosts, 7 days | **Simulated only** | 30 agent state dirs on one Linux box, 7 cycles of 2 to 3 minutes, 4 injected faults, on SQLite and Postgres. 210 of 211 ingests succeeded; the one failure is the injected revoked-host 401. The real run was not done (see Not run here). `benchmark/fleet/SOAK.md`, `benchmark/fleet/results/soak-simulated-*.json`. |
| 2 | Detection accuracy | **PASS, with limits** | 176 labelled cases (96 positive, 80 negative). Precision 1.000 excluding 8 named accepted false positives (raw 0.922). Recall 0.990 (TP 95, FP 0, FN 1). Limits: the corpus is synthetic and written for pqcscan, each probe has a handful of cases, there is no `net.tls.https` negative, and the one miss is the mTLS endpoint. `docs/ACCURACY.md`, `benchmark/corpus/accepted_fp.txt`. |
| 3 | Load, p95 < 2 s at 500 hosts | **FAIL** | 500 hosts: SQLite p95 8.6 s, Postgres 61 s with 471 client timeouts. See F7. `benchmark/fleet/LOAD.md`. |
| 4 | Threat model and fuzz | **PASS** | 57 STRIDE rows over 7 surfaces, each with a named owner. 42 fuzz tests on `load_bundle`, `parity_key` and label parsing. Three product bugs fixed (F11). Rows with no covering test are stated in the table: E7, I10, X5, D6, S5, T5. `docs/security/THREAT-MODEL-FLEET.md`, `tests/fuzz/`. |
| 5 | Bake-off | Delivered | anvilsecure/pqcscan 0.8.0, QuantaSeek 0.1.0 and csnp/cryptoscan 1.4.1 on the corpus's TLS endpoints, certificate files and source tree, not on container images. `docs/BAKEOFF.md`. Findings F3, F4. |
| 6 | Acceptance reconciliation | Tooling delivered; **run blocked** | No prospect hosts or inventory exist. `benchmark/fleet/reconcile.py` and `docs/ACCEPTANCE-TEMPLATE.md` are ready. Finding F1 blocks the CN check. |

## How the claims are graded

- **Evidenced.** A test, CI job or measured artefact backs the claim, and it is named.
- **Simulated.** Only the simulated soak or the loopback load run backs it.
- **Asserted.** Nothing here backs it, or only a text check that never executes the thing.
- **Contradicted.** Evidence says otherwise. The finding is linked.

Evidence keys used in the table:

| Key | What it is |
|---|---|
| UT | Full suite, `.venv/bin/python -m pytest -q -p no:cacheprovider`, at `cd8f8d6`: 1813 passed, 6 skipped, 42 fuzz tests deselected by default. The tests are named per row. |
| PG | `verify.yml` job `postgres`: 9 fleet test files on `postgres:16-alpine`, 120 passed, 0 skipped. 13 of them are SQLite-only or touch no database. Run 39037633212 at `f90c0bf`. |
| FZ | `verify.yml` job `fuzz`: `pytest -m fuzz tests/fuzz`, 42 passed at 500 examples. Same run. |
| WIN | `verify.yml` job `windows-installer`: 28 Pester tests of `packaging/fleet/windows-task.ps1` on `windows-2022` and `windows-latest`. Same run. |
| LOAD | `benchmark/fleet/LOAD.md` and `results/load-*.json`. Locust and the collector share one 8-core box on loopback. Bundles hold 300 findings. |
| SOAK | `benchmark/fleet/SOAK.md` and `results/soak-simulated-*.json`, run 3. SQLite at `e4c753c`, Postgres at `9d086c3`. Simulated. |

## Claims in FLEET.md

| Section | Claim | Evidence | Status |
|---|---|---|---|
| 1 Collector | `--enroll-token` enables enrollment; without it the endpoint is off | UT `test_daemon_fleet.py::test_enroll_disabled_is_503_without_parsing_the_body` | Evidenced |
| 1 | Agents use their own bearer token; the proxy must not add basic auth on the two agent paths | UT `test_daemon_fleet.py::test_fleet_paths_bypass_site_cookie_guard`, `test_fleet_threat_model_gaps.py::test_bearer_bypass_is_exact_for_the_two_fleet_paths` | Evidenced |
| 1 | The nginx recipe handles those paths; `--tls-cert/--tls-key` serve TLS | Nothing runs nginx, and LOAD and SOAK use plain http on loopback | Asserted |
| 2 Host | The first run enrolls and stores the token in `agent.token` mode 0600; later runs reuse it | UT `test_cli_report.py::test_enroll_writes_token_0600_and_reuses_it`; SOAK cycle 1 (30 of 30 enrolled) | Evidenced |
| 2 | With the collector down the bundle is spooled and sent on the next run | UT `test_cli_agent.py::test_cycle_spools_on_5xx_then_flushes`, `integration/test_fleet_spool.py`; SOAK cycles 2 and 3 (30 spooled, 0 left, 60 stored) | Evidenced |
| 2 | Plain `http` is refused unless loopback or `--allow-http` | UT `test_cli_report.py::test_scan_cli_refuses_plain_http_without_allow_http`, `test_daemon_guard.py::test_is_loopback` | Evidenced |
| 3 Fleet view | `/api/fleet`, `fleet summary` and `/fleet` list every host with band and counts; label filter works | UT `integration/test_ui_fleet.py::test_fleet_page_lists_hosts_and_filters`, `integration/test_fleet_e2e.py::test_two_hosts_report_and_fleet_exports` | Evidenced |
| 3 | The stale flag marks hosts not seen for 48 hours | UT `integration/test_ui_fleet.py::test_fleet_host_page_and_stale_flag` (flags only the stale host) | Evidenced |
| 3 | `drift N` marks a host whose latest scan changed | JSON count: UT `test_daemon_fleet.py::test_fleet_summary_reports_drift_count`. Chip markup in `fleet.html` has no test. Before `91372e4` and `e4c753c` every host showed drift (F8, F9) | Evidenced after fixes |
| 3 | Labels `data_lifetime`, `migration_years`, `threat_years` set the Mosca inputs; invalid ones are ignored; an invalid value resets a label | UT `test_labels_risk_inputs.py` (`test_mosca_from_labels`, `test_mosca_from_labels_rejects_bad_values`, `test_bad_labels_fall_back_to_default`) | Evidenced |
| 3 | Labels merge and a dropped label stays | UT `test_fleet_repo.py::test_merged_host_labels_stop_at_the_cap_and_never_refuse_the_scan` | Evidenced |
| 3 Agility | Score 0 to 100, bands at 70 and 40, info and drift ignored, nothing vulnerable gives 100; config edit 90, hardware 10 | UT `test_agility.py` (`test_score_findings_weights_vulnerable_only`, `test_band_thresholds_and_ibmi_sysval`, `test_fleet_drift_and_fleet_attribution_ignored`). The per-source numbers are a design choice and nothing checks that they are right | Evidenced |
| 3 | The fleet export's score is the mean over all hosts' findings, so large hosts dominate | No fleet-level test | Asserted |
| 4 Exports | `export --scan fleet` and `GET /api/scans/fleet/export/<fmt>` build from the latest scan of each host, attributed via `evidence._fleet` | UT `integration/test_fleet_e2e.py::test_two_hosts_report_and_fleet_exports`, `test_daemon_fleet.py` export tests. `reconcile.py` reads a real fleet CBOM. Not measured at fleet scale (F13) | Evidenced; scale Asserted |
| 5 Parity | `diff --parity --fail-on-drift` exits 1 only on real differences; `merge` folds per-host DBs | UT `test_parity_drift.py::test_parity_diff_cli_fails_on_real_difference`, `test_diff_cli_parity_ignores_host_names`, `test_fleet_merge_diff.py::test_merge_and_diff_cli`; FZ `test_fuzz_parity.py` | Evidenced |
| 6 Admin | `agents list` shows first and last seen; `revoke` blocks; `unrevoke` lets the host re-enroll and replay its spool; `fleet prune` | UT `test_cli_fleet_admin.py`; SOAK host 5 (401, enroll 403, then enroll 201 and 3 bundles stored). Soak is simulated | Evidenced |
| 7 Scale | SQLite handles roughly 2,000 hosts daily | LOAD: p95 < 2 s held at 120 hosts posting every minute in both seeds. 2,000 daily is about 1.4 posts per minute, or about 17 with the 2 h jitter. A herd of 500 at once fails (F7). Real bundles are about 1,670 findings, not 300 (F19) | Evidenced by rate arithmetic |
| 7 | Past roughly 10k hosts a day use Postgres | LOAD shows Postgres no faster than SQLite and unprofiled (F20). The threshold rests on write concurrency, which no run tested | Asserted |
| Retention | Daemon keeps the newest 12 scans per host after each ingest; minimum 2; the new scan is never removed; others untouched; a duplicate prunes nothing | UT `test_fleet_repo.py::test_prune_host_keeps_newest_n_and_leaves_other_hosts_and_rollups`, `test_daemon_fleet.py::test_ingest_prunes_to_keep`, `::test_daemon_keep_scans_per_host_minimum_is_two`; SOAK pruned [0, 0, 0, 29, 29, 32, 30] at keep 3, as modelled; replayed duplicate stored no scan | Evidenced |
| Retention | A failed prune does not fail the ingest; baselines are never pruned; failed scans count but the newest completed scan is kept | UT `test_daemon_fleet.py::test_ingest_succeeds_when_prune_fails`, `test_fleet_repo.py::test_prune_host_never_deletes_baselined_scans`, `::test_prune_host_keeps_newest_done_scan_behind_failed_ones` | Evidenced |
| Agent loop | Backoff from 1 minute to 1 hour; permanent rejection (400, 403, 413) is not spooled; SIGTERM stops cleanly; state dir 0700; local DB trimmed to `--keep-local`; `--interval` above zero; `--once` exit codes | UT `test_cli_agent.py` (`test_next_delay_backoff_and_jitter`, `test_cycle_permanent_rejection_is_neither_reported_nor_spooled`, `test_sigterm_stops_loop_cleanly`, `test_state_dir_created_0700`, `test_local_db_pruned_to_keep_local`, `test_cmd_rejects_non_positive_interval`, `test_cmd_once_exits_one_on_permanent_rejection`). The loop ran for seconds in tests, never for days. SOAK used `--once`, the recommended mode | Evidenced |
| Recipes | systemd unit runs as a dedicated user with `ProtectSystem=strict` | UT `test_fleet_recipes.py::test_service_is_sandboxed_and_not_root` parses the unit text. No systemd ran it | Asserted |
| Recipes | Ansible, BigFix and Wazuh/osquery recipes work | UT `test_fleet_recipes.py` checks YAML and text only | Asserted |
| Recipes | No recipe skips TLS verification | UT `test_fleet_recipes.py::test_no_recipe_skips_tls_verification` | Evidenced |
| Recipes | `windows-task.ps1` downloads the pinned exe into Program Files, checks its SHA-256, locks the state folder, refuses to run over an install, registers a daily 02:00 task | WIN on both runners. The 2 h random delay is not asserted. Windows Server 2019 and Windows 11 were not run | Evidenced |
| Recipes | The state folder grants the task account Modify | WIN checks the ACLs for a dedicated account, but the install cannot finish for a non-SYSTEM account (F6) | Contradicted, F6 |
| Recipes | Rotating the enroll token leaves enrolled hosts working | UT `test_cli_report.py::test_agent_token_bypasses_enroll`; ingest authenticates by token hash, not by the enroll token | Evidenced |
| Recipes | A `machine_id` mismatch gets 403 and a spooled 403 file moves to `spool/rejected/` | UT `test_fleet_threat_model_gaps.py::test_one_hosts_token_cannot_post_as_another_host`, `test_cli_report.py::test_flush_spool_moves_413_file_and_sends_the_rest` | Evidenced |
| Drift | One `fleet.drift` row per finding that appeared or vanished, none for a first, failed or interrupted scan, excluded from counts, reported as `drift` in the response | UT `test_parity_drift.py` (`test_drift_rows_added_and_removed`, `test_ingest_emits_drift_against_previous_scan`, `test_drift_rows_never_count_toward_readiness_or_totals`); SOAK drift 6 rows, all from the one host whose cert dir was changed. Before the fixes the claim was false (F8, F9) | Evidenced after fixes |
| Drift | At most 500 rows per scan then one summary row; over 50,000 findings only the summary | UT `test_parity_drift.py::test_drift_rows_capped_with_summary_and_true_total`; FZ `test_drift_rows_cap_is_enforced_with_a_summary`, `test_drift_rows_above_the_normalise_ceiling_count_raw_titles` | Evidenced |
| Drift | The match key ignores host names, addresses and `at <host>` | UT `test_parity_drift.py::test_parity_key_strips_endpoints`, `test_parity_key_host_literals_and_server_attribution`; FZ | Evidenced |
| Security | The enroll token holder can enroll any machine id; enrollment is not rate limited | UT `test_reenroll_logs_warning_and_rotates_token` pins the first. The second has no test (row E7), accepted risk AR2 | Evidenced; no throttling Asserted |
| Security | A revoked host cannot re-enroll until unrevoked | UT `test_daemon_fleet.py::test_revoked_host_cannot_reenroll_until_unrevoked`; SOAK host 5 | Evidenced |
| Security | The agent token file is 0600 and written without following symlinks | UT `test_cli_report.py::test_write_private_refuses_symlink_and_exclusive_existing` | Evidenced |
| Security | The collector stores only token hashes | UT `test_daemon_fleet.py::test_enroll_then_ingest_then_fleet` finds the host by `hash_token(agent_token)`. No test scans the DB for the raw token | Evidenced |
| Security | Ingest caps: 8 MiB wire, 50 MiB raw, 200,000 findings | UT `test_bundle.py::test_load_rejects_oversize`, `::test_load_rejects_too_many_findings`, `test_daemon_fleet.py::test_chunked_oversize_upload_is_413`; FZ `test_valid_gzip_of_arbitrary_bytes` | Evidenced |
| Security | Burst of 10 bundles, one per minute refill; a duplicate spends a token; the 11th post in a row gets 429 | UT `test_daemon_fleet.py::test_token_bucket_every_outcome_spends_a_token`; SOAK 10 duplicates answered 200 then 429, on both DBs. FLEET.md said a duplicate was free until `4cf62a5` (F10) | Evidenced after fix |
| Security | Label caps 64 per host, 64 characters per key, 256 per value; new keys beyond 64 are dropped and logged; the scan is stored | UT `test_fleet_repo.py::test_host_already_over_the_cap_keeps_labels_and_still_ingests_and_enrolls`, `test_bundle.py::test_load_caps_host_labels`; FZ `test_host_labels_never_exceed_the_cap_across_bundles`. Before the fix the cap was per bundle (F11) | Evidenced after fix |
| Security | The bundle `machine_id` must match the token | UT `test_fleet_threat_model_gaps.py::test_one_hosts_token_cannot_post_as_another_host` | Evidenced |
| Security | Findings never carry key bytes; machine ids are domain-separated hashes | Threat row I10: no fleet-level test, enforced per probe | Asserted |
| Known limits | No split-and-resend on 413; a scan over the raw cap fails to dump | No test | Asserted |
| Known limits | 400, 403, 413 are never spooled at ingest; a revoked host's bundles spool and replay; nothing prunes `spool/rejected/` | UT `test_cli_agent.py::test_cycle_permanent_rejection_is_neither_reported_nor_spooled`; SOAK host 5 replay; the unpruned directory is accepted risk AR5 | Evidenced |
| Known limits | Ingest capacity: 60 to 250 hosts on SQLite (120 passes both seeds), 30 to 60 on Postgres; 500 not met (SQLite 8.6 s, Postgres times out) | LOAD: figures match the result files. The band is for 300-finding bundles on a shared, loaded box | Evidenced, F7 |
| Known limits | "Postgres is wired but untested; the fleet test suite runs on SQLite only" | PG: 120 tests pass on `postgres:16-alpine`. The sentence is out of date (F14) | Contradicted, F14 |

## Findings

Severity is the author's reading of impact on a fleet deployment. "Fixed" means the commit is on this branch and a test covers it.

| ID | Finding | Severity | State | Owner | Source |
|---|---|---|---|---|---|
| F7 | **Ingest misses the 2 s target at 500 hosts on both databases.** Two bounded fixes did not close it: bulk insert without RETURNING (`05289fd`, `c4fe5b3`) and enroll and token lookup off the event loop (`41b9dea`, `2b48ece`). Capacity at p95 < 2 s with per-minute posting: SQLite 60 to 250 hosts (120 passes both seeds), Postgres 30 to 60. At 500 hosts SQLite p95 is 8.6 s and Postgres 61 s with 471 client timeouts. At overload the server keeps working on requests the client abandoned (581 scans stored for about 240 client successes, Postgres, `97c8578` run). There is no load shedding. The host and revoke routes still make synchronous repo calls on the event loop. Spec item 3 fails. | High | Open | Product | LOAD.md, task 2 |
| F19 | The load run posts 300-finding bundles. A real scan stores about 1,670 findings. In the soak, with six agents posting at once, collector-side ingest p95 was 0.6 to 7.9 s on SQLite and 6.0 to 10.6 s on Postgres. Real capacity is therefore likely below the F7 band. Unmeasured. | High | Open | Product | SOAK.md finding 4 |
| F20 | Postgres is no faster than SQLite under this load, and the cause is not profiled. After the fix: 10 statements per ingest on both, yet Postgres capacity is lower. | Medium | Open | Product | LOAD.md |
| F1 | The fleet CBOM carries no certificate subject, so CN-level reconciliation against a prospect inventory is impossible. The CBOM also has no structured TLS version (`reconcile.py` parses it from the description text), and `fleet summary --json` lacks machine id, last seen and revoked. | High for acceptance | Open | Product | task 6, `reconcile.py` |
| F6 | Running `windows-task.ps1` with a non-SYSTEM `-RunAs` account fails at task registration, after the folders, binary, wrapper and `agent.env` are written. It leaves a half-finished install. The Pester suite asserts the failure so it will break when the installer is fixed. | Medium | Open | Packaging | task 7, `windows-task.Tests.ps1` |
| F9 | `net.ports.tcp` reported open ports as closed when synchronous database writes blocked the event loop. Fleet drift then showed paired removed and added rows on unchanged hosts. 2 of 12 concurrent scans lost all four ports before the fix, 0 of 12 after (`e4c753c`). | High | Fixed | Product | SOAK.md finding 2 |
| F15 | About 28 other probes time a connect inside the event loop (`grep open_connection src/pqcscan/probes`). They were not checked for the F9 weakness. | Medium | Open | Product | SOAK.md finding 2 |
| F8 | `aux.clock.cert_validity` put the scan time in its title, so every host reported drift on every scan. Fixed in `91372e4`. | High | Fixed | Product | SOAK.md finding 1 |
| F10 | FLEET.md said a duplicate resend is free. A duplicate spends a token: 10 return 200 then 429. The doc was corrected in `4cf62a5`. | Low | Fixed | Docs | SOAK.md finding 3 |
| F11 | Fuzzing found three bugs, all fixed. A truncated gzip body was accepted (`6107692`). A parity key could outgrow its 512 character cap (`bf8c701`). The 64 label cap held per bundle, not per host (`985499c`, then `5d3dd6c` so a host already over the cap keeps reporting). | Medium | Fixed | Product | task 1 |
| F12 | The bulk insert first needed SQLite 3.35 for RETURNING, which would have returned 500 on every ingest on RHEL 9 (SQLite 3.34). Fixed in `c4fe5b3`; SQLAlchemy is pinned at 2.0.10 or newer. | High | Fixed | Product | task 2 |
| F2 | `code.crypto_primitives` had precision 0.302 on comment and string negatives, and was missing from the accuracy corpus. Now 1.000 excluding 8 accepted fail-open false positives (C, C++, Ruby, Swift), raw 0.733 for that probe. Fixed in `4df285e`, `7469e2a`, `d0d97ce`. | Medium | Fixed, limit stays | Product | ACCURACY.md |
| F5 | XMSS, LMS and HSS were not classed PQC. Fixed in `d9e3b84`. | Low | Fixed | Product | BAKEOFF.md |
| F16 | The first accuracy pass scored five probes under 0.9 (precision 0.955 and recall 0.913 overall): `code.ts.java`, `fs.keystore.pkcs12`, `net.tls.versions`, `net.tls.pqc_handshake`, `net.tls.https`. All fixed with tests. A simulated OpenSSL 3.0 recall of 0.985 hid a real miss: CI measured 0.973 on OpenSSL 3.0.13, and `2fc607a` fixed `net.tls.pqc_handshake` there (CI then 0.986). | Medium | Fixed | Product | ACCURACY.md |
| F17 | Known accuracy limits: single DES goes unreported in languages without a `code.ts.*` probe; a PHP 8 attribute line hides code after it; `net.tls.https` misses the mTLS endpoint (`net.tls.cert_chain` covers it); comment mentions in C, C++, Ruby and Swift fire by design. | Low | Open, accepted | Product | ACCURACY.md Limits |
| F3 | Only the preferred TLS key exchange group is reported. anvilsecure/pqcscan lists every group the server accepts. | Medium | Open, backlog | Product | BAKEOFF.md |
| F4 | Go `ecdsa.GenerateKey` is missed by `code.ts.go`. SHA-384 and SHA-512 are not listed (low priority). | Low | Open, backlog | Product | BAKEOFF.md |
| F13 | Threat rows X5 and U5 say the load run covers the fleet export and `/fleet` page at 2,000 hosts. It did not: the load harness posts bundles only, and no run exceeded 500 hosts. Export and page latency at scale are unmeasured. | Medium | Open | Maintainers | THREAT-MODEL-FLEET.md |
| F14 | FLEET.md Known limits and threat risk AR6 say Postgres is untested. The CI job runs the fleet tests on Postgres. The docs understate the evidence. | Low | Open | Docs | `verify.yml` |

Smaller open items. The duplicate-recovery lookup that answers 503 on a busy store has no test. The two benchmark smoke tests run in the default CI job, about 50 s. Revoke is not attributed to a person, and there is no per-ingest audit line (threat model residual risks). Dropped label keys appear only in the collector log. SQLite file growth was about 1.2 MB per scan on one measurement; extrapolated to the default 12 scans for 2,000 hosts that is about 28 GB (arithmetic, not a test).

## Not run here

These need hosts, data or time this environment does not have. Each ships as a script or runbook, except where noted.

| Not run | Why | How to run it |
|---|---|---|
| Real 30-host, 7-day soak on Linux, Windows and IBM i | No hosts, no 7 days. The simulation says the code paths match FLEET.md, not that real networks, clocks, Windows or systemd timers do | `benchmark/fleet/soak-real.md`, collector side `python -m benchmark.fleet.soak --observe` |
| Prospect acceptance reconciliation | No prospect inventory or hosts, and F1 blocks the CN check | `docs/ACCEPTANCE-TEMPLATE.md`, `benchmark/fleet/reconcile.py` |
| Windows Server 2019 and Windows 11 | GitHub retired Server 2019 runners; CI runs `windows-2022` and `windows-latest` | Run `packaging/fleet/windows-task.Tests.ps1` on those images |
| Postgres profiling | Not done; F20 stays unexplained | Profile one ingest with `EXPLAIN` and pg_stat_statements under `run_load` |
| `soak --observe` against a real fleet | One automated test and a toy database only | `soak-real.md` section on observation |
| Accuracy CI on the final 176-case corpus | CI last measured an earlier, smaller corpus (recall 0.986 on OpenSSL 3.0.13, 8 hybrid cases skipped). The numbers above are local, on OpenSSL 3.5.7 | Push the branch and read the `accuracy` job |
| Load at real bundle size, and the fleet export and `/fleet` at scale | F19, F13 | `run_load --findings-per-bundle 1700`; add an export timing step |

## Reproduce

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider                      # UT
PYTHONPATH=src .venv/bin/python -m pytest -m fuzz tests/fuzz            # FZ (PQCSCAN_FUZZ_EXAMPLES=500 in CI)
PYTHONPATH=src python benchmark/run_benchmark.py --by-family --accept-fp-file benchmark/corpus/accepted_fp.txt --min-precision 1.0 --min-recall 0.95
python -m benchmark.fleet.run_load --db sqlite --hosts 500 --spawn-rate 50 --duration 120s --findings-per-bundle 300
python -m benchmark.fleet.soak --db sqlite --hosts 30 --cycles 7 --interval 60 --fault-plan default
PYTHONPATH=src .venv/bin/python benchmark/bakeoff/run_bakeoff.py --date 20261017
```

Postgres runs need `PQCSCAN_TEST_DB_URL=postgresql+psycopg://...` for tests, or `--db postgres` with Docker for the load and soak scripts.
