# pqcscan — Fleet / agent mode design

| | |
|---|---|
| **Date** | 2026-10-16 |
| **Project** | pqcscan v2 (`pqc-scanner2`), post-v0.9.13 |
| **Predecessor** | `docs/superpowers/specs/2026-05-07-pqcscan-plan-h-pqc-scope-and-ot-coverage-design.md` (Plan H); "Plan I.1 asset auto-discovery + fleet rollup" named there as future work |
| **Status** | Approved 2026-10-16 (all three phases; SQLite default, Postgres optional; one-shot agent form primary; single tenant per daemon) |
| **Target tags** | v0.10.0 (phase 1) → v0.10.1 (phase 2) → v0.10.2 (phase 3) |

## 1. Problem

One `pqcscan scan` = one host (or one target) = one SQLite DB on that host. An
estate of 2,000 assets means 2,000 manual runs and a hand-collected pile of
DBs (`pqcscan merge` exists since 0.9.13 but still needs the files). There is
no per-host history, no drift detection, no central view. Every commercial
peer (SandboxAQ, Keyfactor/AgileSec, PQ Crypta, HCL BigFix QRA) ships a
push-model agent plus a collector; that, not detection, is what enterprises
buy.

## 2. Decision

**Approach A — push agent = existing binary + `--report-to`; the daemon is the
collector.** No new binary, no new long-running process required on hosts.

- Hosts run `pqcscan scan --report-to <url> --agent-token <t>` from the
  customer's own scheduler (cron, systemd timer, Task Scheduler, BigFix,
  Ansible). A `pqcscan agent` loop exists for hosts with no scheduler.
- Results travel as one gzip JSON **ScanBundle** to `POST /api/ingest` on the
  daemon, which gains enrollment, a `hosts` table, per-host history, a
  `/fleet` page and fleet-wide exports.
- Rejected: a custom per-host supervisor (second root process, per-OS service
  wrappers, update logistics); agentless SSH/WinRM runner (credential vault for
  2,000 hosts, no persistence) — documented as a later complement; EDR-only
  recipes (converge on this server side anyway) — shipped as docs.

## 3. Architecture

```
host (any OS)                              daemon (collector)
┌────────────────────────────┐            ┌─────────────────────────────────┐
│ pqcscan scan --report-to   │  HTTPS     │ POST /api/agents/enroll          │
│   └ ScanBundle (gzip JSON) ├───────────►│ POST /api/ingest   (bearer token)│
│ pqcscan agent (loop,       │  bearer    │   ├ validate, size cap, rate cap │
│   spool + backoff)         │            │   ├ upsert hosts, insert scan    │
│ state dir: token, spool/   │            │   └ return stored counts         │
└────────────────────────────┘            │ store: hosts, scans.host_id      │
                                          │ GET /fleet, /fleet/{host}        │
                                          │ export --scan fleet (rollup)     │
                                          └─────────────────────────────────┘
```

### 3.1 Units

| Unit | File | Responsibility | Depends on |
|---|---|---|---|
| `ScanBundle` | `store/bundle.py` | `dump(repo, scan_id) -> bytes` (gzip JSON) and `load(bytes) -> Bundle`; `schema_version`, `scan_uuid`, host identity (`machine_id`, `hostname`, `os`, `labels`, `agent_version`), scan row, findings with their framework views, probe-error rows; hard cap 50 MB uncompressed | `Repo`, `schema` |
| `scan --report-to` | `cli/scan.py` | After `finish_scan`, build the bundle and POST; on any failure write to the spool dir and still exit by the gate rule (scan succeeded) | `ScanBundle`, `httpx` |
| `pqcscan agent` | `cli/agent.py` | `--server --enroll-token --labels --interval --jitter --once --state-dir --path…`; enrolls once (token file 0600), then loop: flush spool → scan → post; exponential backoff on 5xx/unreachable; 401 → re-enroll once then stop; 413 → split by probe family | `scan --report-to` |
| `daemon/fleet.py` | new | `POST /api/agents/enroll` (shared enrollment token → per-agent token, stored as SHA-256), `POST /api/ingest` (bearer = agent token; schema + size + machine-id-matches-token checks; one transaction; idempotent on `scan_uuid`; 1 bundle/min/agent), `GET /api/fleet`, `GET /api/fleet/{host_id}`, `POST /api/agents/{id}/revoke` | `Repo`, `ScanBundle`, existing guard |
| Store | `store/schema.py`, `store/migrations.py`, `store/repo.py` | `hosts(id, machine_id UNIQUE, hostname, os, labels JSON, agent_version, first_seen, last_seen, token_hash, revoked)`, `scans.host_id`, `scans.scan_uuid UNIQUE`; `upsert_host`, `fleet_summary()` (latest done scan per host + readiness + crit/high + drift vs previous), `host_history(host_id)`, `prune_scans(keep_per_host)`, `fleet_rollup_scan()` (computed latest-per-host rollup reusing `store/merge.py` logic) | migrations |
| Fleet UI | `ui/routes.py`, `templates/fleet.html`, `templates/fleet_host.html`, i18n keys | `/fleet` table (host, labels, last seen, readiness, crit/high, drift badge, stale > 2×interval); label filter; `/fleet/{host}` history + link to diff | `_render`, bands |
| Fleet exports | `cli/export.py`, `daemon/app.py` | `--scan fleet` → rollup scan (materialised on demand into a temp scan row, deleted after export) so CBOM/SARIF/BUKUKERJA/PDF are unchanged | `merge.py` |
| Drift | `store/repo.py` + ingest | On ingest, diff vs the host's previous done scan with a host-agnostic parity key; emit synthetic `fleet.drift` findings into the new scan so they flow through compliance/SARIF/BUKUKERJA | `diff_findings` |
| Labels → risk | `core/mosca.py`, `core/exposure.py` callers | Per-host `labels` (`data_lifetime`, `criticality`) override the global CLI flags when building report context for a host or the fleet | report context |
| Crypto-agility | `core/agility.py` | 0–100 per finding and per host from (probe id, evidence kind): config-sourced / library-sourced / KMS-referenced score high; hardcoded source / binary constant / appliance-pinned / hardware-bound score low; surfaced in reports and BUKUKERJA `crypto_agility` column | findings |
| CLI admin | `cli/fleet.py` | `pqcscan agents list|revoke`, `pqcscan fleet prune --keep N`, `pqcscan fleet summary` | repo |

### 3.2 Data flow

1. Operator: `pqcscan daemon --bind 0.0.0.0 --token T --enroll-token E --tls-cert … --tls-key …` (or behind the nginx recipe with `--allow-host`).
2. Host first run: enroll → agent token saved in `<state-dir>/agent.token` (0600) with `machine_id` (Linux `/etc/machine-id`, Windows `MachineGuid`, macOS `IOPlatformUUID`; fallback SHA-256 of hostname+primary MAC).
3. Scan → bundle → `POST /api/ingest` → daemon upserts host, inserts scan+findings+views in one transaction, computes drift, returns `{scan_id, stored_findings, stored_views, duplicate}`.
4. `/fleet` reads `fleet_summary()`; exports read the computed rollup.
5. Retention: `prune_scans(keep_per_host=12)` on ingest and via CLI.

### 3.3 Security

- Enrollment token bootstraps only; per-agent tokens hashed at rest, revocable; a revoked token's ingest is 401.
- `/api/ingest` and `/api/agents/enroll` are bearer-only (cookie sessions never accepted), size-capped (50 MB gzip-expanded, streamed), rate-limited per agent; `machine_id` in the bundle must match the token's host.
- Host allowlist, Origin guard, non-loopback-needs-token rules from 0.9.13 stay. Plain-HTTP ingest on a non-loopback bind logs one warning.
- Findings never carry key bytes (probe-level redaction already enforced); spool dir and token file are 0700/0600.

### 3.4 Scale

- Target: 2,000 hosts daily × ~2,000 findings = 4 M rows/day before pruning. SQLite WAL with one writer thread (ingest queue) is sufficient; pruning keeps the DB bounded (~12 scans/host).
- Above ~10k hosts/day: `--db postgresql://…` — SQLAlchemy already supports it; the SQLite PRAGMA listener becomes conditional on the dialect; `psycopg[binary]` added to a `[fleet-pg]` extra, not to the base binary.
- Bundle size: ~300 KB gzip per 2,000-finding scan.

### 3.5 Error handling

| Case | Agent | Server |
|---|---|---|
| Server unreachable / 5xx | spool bundle, retry next cycle with backoff (1 m → 1 h cap) | — |
| 401 | re-enroll once with the enrollment token; if that fails, stop and log | token unknown/revoked |
| 413 | split bundle by probe family, resend parts (same `scan_uuid`, `part/of`) | server merges parts |
| Duplicate `scan_uuid` | treat 200 `duplicate:true` as success, drop spool | no second insert |
| Bad schema | log, keep in spool for manual inspection, continue | 400 with field name |
| Partial insert | impossible | single transaction |

## 4. Testing

- Unit: bundle round-trip incl. framework views; enroll/ingest with `TestClient` (good token, bad token, revoked, wrong machine id, oversize, duplicate uuid, rate limit); `fleet_summary`, `host_history`, `prune_scans`; drift emission with parity key; agility score table; agent `--once` against a fake server (success, 5xx→spool, 401→re-enroll).
- Integration: two agents (subprocess, `--once`) → live daemon on a free port → `/fleet` lists both, fleet CBOM has both hosts, `pqcscan diff` across them, `/api/fleet` JSON.
- Load: script posts 500 bundles concurrently; assert zero lost findings, p95 ingest < 2 s on SQLite.
- Cross-OS: `machine_id` resolution safe on Linux/macOS/Windows (test with monkeypatched paths).

## 5. Phases

| Phase | Scope | Tag |
|---|---|---|
| 1 | `ScanBundle`; `scan --report-to`; enroll + ingest + revoke; `hosts` table + migrations; `fleet_summary`/`host_history`/`prune`; `export --scan fleet`; `pqcscan agents list|revoke`; `pqcscan fleet summary|prune`; docs | v0.10.0 |
| 2 | `pqcscan agent` loop (spool, backoff, re-enroll, split-on-413); `/fleet` + `/fleet/{host}` pages (EN/MS); deployment recipes: systemd timer, Windows Task Scheduler XML, Ansible playbook, BigFix fixlet stub, osquery/Wazuh note | v0.10.1 |
| 3 | Drift findings (`fleet.drift`) with host-agnostic parity key; per-host labels into Mosca/exposure; `core/agility.py` crypto-agility score in reports + BUKUKERJA; retention defaults | v0.10.2 |

## 6. Non-goals

Multi-tenant isolation (one daemon per entity for now); agentless SSH/WinRM
runner; runtime call tracing; remediation execution; IBM i agent (IBM i stays
export-based via `fs.conf.ibmi_sysval` + DCM PEM exports, scanned by a
Linux/Windows collector host with `--path`, which can itself report via
`--report-to` with `--labels host=<lpar>`).
