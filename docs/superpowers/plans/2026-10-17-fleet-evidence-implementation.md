# Fleet Mode Evidence Campaign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Produce independent, re-runnable evidence that fleet mode works, and a list of where it does not.

**Architecture:** Every workstream is a script or test that writes a dated artefact (JSON + Markdown) under `benchmark/fleet/results/` or `docs/`, each stamped with the command and commit. No product code changes except bug fixes the evidence forces.

**Tech Stack:** Python 3.11, pytest, hypothesis, locust, psycopg 3, Docker (postgres:16-alpine, rust:1-slim), GitHub Actions (Pester on Windows, Postgres service).

**Spec:** `docs/superpowers/specs/2026-10-17-fleet-evidence-spec.md`

## Global Constraints
- No new product features; code under `benchmark/`, `tests/`, `docs/`, `.github/`, `pyproject.toml` (`verify` extra) only — a product bug the evidence uncovers may be fixed in `src/` with its own test and CHANGELOG line.
- Python >= 3.11; line length 120; `ruff check src tests benchmark` clean; `mypy src/pqcscan` clean.
- Artefacts name the exact command and the git commit; results dirs are committed.
- Simulated results are labelled "simulated" in the file name and the first line.
- Commit trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`; no push/PR/tag by implementers.

---

### Task 1: Threat model + fuzz targets (spec item 4)
**Files:** Create `docs/security/THREAT-MODEL-FLEET.md`, `tests/fuzz/__init__.py`, `tests/fuzz/test_fuzz_bundle.py`, `tests/fuzz/test_fuzz_parity.py`, `tests/fuzz/test_fuzz_labels.py`; Modify `pyproject.toml` (`verify = ["hypothesis>=6.100", "locust>=2.29", "psycopg[binary]>=3.1"]`), `pytest.ini`/`pyproject` markers if needed.
**Produces:** STRIDE table (rows: enroll, ingest, fleet export, agent state dir, spool, token file; columns S/T/R/I/D/E) where every abuse case names the test or fuzz target that covers it and the residual risk with an owner; hypothesis tests: `load_bundle` never raises anything but `BundleInvalid`/`BundleTooLarge` on arbitrary bytes and arbitrary JSON documents (incl. nested, huge labels, non-str values); `parity_key` is total, deterministic, returns bounded strings (≤ 600 chars each) and runs < 50 ms on 50 kB titles; `mosca_from_labels`/`check_labels` never raise. Fuzz tests run under `-m fuzz` with `max_examples=200` default, `PQCSCAN_FUZZ_EXAMPLES` env to raise.
**Steps:** write failing fuzz tests → run → fix any product bug found (own commit, CHANGELOG line) → write the threat model → commit `test(fuzz): hypothesis targets for bundle, parity and labels` + `docs(security): fleet threat model (STRIDE)`.

### Task 2: Load test harness (spec item 3)
**Files:** Create `benchmark/fleet/__init__.py`, `benchmark/fleet/_collector.py` (start/stop a `create_app` daemon on a free port in a thread or subprocess, SQLite path or Postgres URL; start/stop `postgres:16-alpine` via `docker run` with a random port and `pg_isready` wait), `benchmark/fleet/_bundles.py` (build N realistic bundles from one real local scan: `dump_bundle` with per-host machine ids/hostnames/labels, optional finding-count scaling), `benchmark/fleet/locustfile.py` (one user per simulated host: enroll once, then POST a bundle; respects 429 as "throttled" not failure), `benchmark/fleet/run_load.py` (CLI: `--db sqlite|postgres --hosts 500 --spawn-rate 50 --duration 120s --findings-per-bundle 300`; runs locust headless, parses `--csv` stats, writes `benchmark/fleet/results/load-<db>-<date>.json` + appends a row to `benchmark/fleet/LOAD.md` with p50/p95/p99, RPS, error rate, 429/503 counts, and PASS/FAIL against p95 < 2 s), `benchmark/fleet/README.md`.
**Produces:** `run_load.py` artefacts for SQLite and Postgres at 500 hosts; a unit test `tests/benchmark/test_fleet_load_smoke.py` running 5 hosts for 10 s on SQLite (marked `benchmark`).
**Steps:** collector helper + test → bundle builder + test → locustfile → runner → run both DBs → commit `bench(fleet): locust load harness and 500-host results (sqlite, postgres)`.

### Task 3: Simulated soak (spec item 1)
**Files:** Create `benchmark/fleet/soak.py` (CLI: `--hosts 30 --cycles 7 --interval 60 --db sqlite|postgres --fault-plan default`), reuse `_collector.py`; each simulated host = own state dir, `PQCSCAN_TEST_MACHINE_ID`, hostname, labels, `--path` to a small per-host fixture dir seeded with a cert; runs the REAL `pqcscan agent --once` subprocess per host per cycle (fast registry via `--path` scope). Fault plan: cycle 2 collector down for 1 cycle (expect spool then drain), cycle 3 revoke host 5 then unrevoke at cycle 5 (expect 401→403 spool, replay), cycle 4 change `--path` for host 7 (expect drift rows), cycle 6 replay a duplicate bundle for host 9 (expect duplicate=true, token spent). Metrics from the collector DB and the agent stderr: ingest success rate, duplicates, 429/503 counts, spool depth per host per cycle, drift rows per host per cycle, prune counts, rejected files. Writes `benchmark/fleet/results/soak-simulated-<db>-<date>.json` and `benchmark/fleet/SOAK.md` with an "expected vs observed" table whose expected column cites the FLEET.md sentence; any unexplained non-zero is listed under "Findings".
**Produces:** SOAK.md for SQLite and Postgres; `benchmark/fleet/soak-real.md` runbook for the real 30-host/7-day soak (same script, `--interval 86400`, hosts enrolled by the shipped recipes).
**Steps:** host simulator + test (3 hosts, 2 cycles, 5 s interval) → fault plan → metrics/report → run 30×7 on both DBs → commit `bench(fleet): simulated soak harness, fault plan and results`.

### Task 4: Accuracy corpus extension (spec item 2)
**Files:** Modify `benchmark/run_benchmark.py` (new fixture kinds: `endpoint` — the harness starts a local TLS server from a YAML spec (cert/key files + min/max TLS version + cipher list + optional client-cert) and points a `net.*` probe at `127.0.0.1:<port>`; `image` — an OCI-layout directory or a tarball for `container.*`/`sbom.*` probes; per-family aggregation `--by-family`), `benchmark/corpus/manifest.yaml` (+≥ 40 cases: RSA-1024/2048/3072/4096, ECDSA P-256/P-384, Ed25519, ML-DSA-65 certs in PEM/DER/PKCS#12; OpenSSH and PKCS#8 keys incl. encrypted; TLS endpoints: TLS 1.0-only, RSA-kex-only, hybrid X25519MLKEM768 negative, weak cipher positive; source snippets for C#, Rust, Kotlin; a small OCI image with an OpenSSL 1.0.2 layer), `benchmark/corpus/generate_fixtures.py` (deterministic generation, seeds, fixture hash file `benchmark/corpus/CORPUS.sha256`), `docs/ACCURACY.md` (per-family P/R table, corpus hash, exact command, commit, list of probes < 0.9 with fix or reason), `tests/benchmark/test_accuracy.py` (family table present; gate unchanged).
**Produces:** `docs/ACCURACY.md`; any probe under 0.9 either fixed in `src/` (own commit) or justified.
**Steps:** fixture generators + hash → harness kinds + tests → manifest cases → run `--by-family` → fixes → docs → commit `bench(accuracy): certs, keys, TLS endpoints, container image; per-family precision/recall`.

### Task 5: Bake-off (spec item 5)
**Files:** Create `benchmark/bakeoff/README.md`, `benchmark/bakeoff/Dockerfile.anvil` (builds anvilsecure/pqcscan at a pinned commit in `rust:1-slim`), `benchmark/bakeoff/Dockerfile.quantaseek` (pinned), optional `Dockerfile.cbomkit` only if a published image exists, `benchmark/bakeoff/run_bakeoff.py` (targets: the Task 4 TLS endpoints, the cert fixtures, one source tree; runs pqcscan + each tool; `normalise.py` maps each tool's output to `{target, surface, algorithm, strength_bits, pq_safe: bool, source_tool}`; writes `benchmark/bakeoff/results/<date>/*.json` and `docs/BAKEOFF.md` with a finding-level set diff per target: pqcscan-only, tool-only, both), `tests/benchmark/test_bakeoff_normalise.py`.
**Produces:** BAKEOFF.md naming what each tool finds that pqcscan misses, with a follow-up line per miss.
**Steps:** Dockerfiles (pinned commits recorded) → normalisers from each tool's real output → runner → run → docs → commit `bench(bakeoff): anvilsecure/pqcscan and QuantaSeek vs pqcscan on shared targets`.

### Task 6: Acceptance tooling (spec item 6)
**Files:** Create `benchmark/fleet/reconcile.py` (inputs: fleet CBOM JSON from `pqcscan export --scan fleet --format cbom`, inventory CSV with columns `hostname,machine_id?,owner,environment,expected_tls,expected_cert_cn`; outputs `discrepancies.csv` + `discrepancies.md`: hosts in inventory not reporting, hosts reporting not in inventory, hostname/machine-id mismatches, expected-vs-observed TLS/cert per host, stale hosts > 48 h), `docs/ACCEPTANCE-TEMPLATE.md` (sign-off sheet: scope, run date, commit, collector URL, discrepancy counts, decision, signatures), `tests/unit/test_fleet_reconcile.py`.
**Produces:** script + template; `docs/ACCEPTANCE-TEMPLATE.md` states that the prospect run is blocked on their data.
**Steps:** test → script → template → commit `bench(fleet): CBOM-vs-inventory reconciliation and acceptance template`.

### Task 7: CI jobs (deliverable)
**Files:** Create `.github/workflows/verify.yml` with jobs: `postgres` (service `postgres:16-alpine`; installs `.[dev,verify]`; runs `tests/unit/test_fleet_*.py tests/unit/test_daemon_fleet.py tests/integration/test_daemon_api.py tests/integration/test_fleet_spool.py` with `PQCSCAN_TEST_DB_URL=postgresql+psycopg://…` honoured by a `conftest.py` fixture override of `tmp_db_path` (returns the URL with a per-test schema or a fresh database created via psycopg) ), `windows-installer` (matrix `windows-2022`, `windows-latest`; Pester 5: runs `packaging/fleet/windows-task.ps1` as shipped against the v0.10.2 release asset with a dummy enroll token and a loopback server URL with `-AllowHttp` if the script has it, else `https://127.0.0.1:9` — asserts: scheduled task registered, ACLs on both folders and `agent.env`, second run refuses with "already exists", a pre-planted junction is refused, task action points at Program Files), `fuzz` (runs `-m fuzz` with 500 examples), `accuracy` (runs `benchmark/run_benchmark.py --by-family --min-precision 1.0`). Modify `tests/conftest.py` (URL override), `docs/CICD.md` (new workflow row).
**Produces:** green runs of all four jobs on the PR.
**Steps:** conftest override + local Postgres run via docker → workflow → Pester tests file `packaging/fleet/windows-task.Tests.ps1` → push branch, iterate until green → commit `ci: verify workflow — postgres, windows installer (pester), fuzz, accuracy`.

### Task 8: Evidence summary (deliverable)
**Files:** Create `docs/FLEET-EVIDENCE.md`: one page, a table of every claim in `docs/FLEET.md` (extract each declarative sentence about behaviour/limits) with columns Claim | Evidence (artefact path + command + commit) | Status (Evidenced / Simulated only / Asserted / Contradicted → finding); a "Findings" list with severity and owner; a "Not run here" list (real soak, prospect acceptance, Server 2019, Windows 11). Modify `CHANGELOG.md` `[Unreleased]`, `README.md` (one pointer line), `docs/STATUS.md`.
**Steps:** extract claims → map to artefacts → write → commit `docs: fleet evidence summary — what is proven, simulated, asserted`.
