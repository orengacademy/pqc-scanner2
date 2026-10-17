# Fleet mode evidence campaign — spec (2026-10-17)

## Request (verbatim from the user)

pqcscan v0.10.2 ships fleet mode (agent, collector, drift, agility, retention). Do not add features. Prove it works and find where it does not, with evidence that does not depend on you or me.

1. **Real-fleet soak.** Stand up a collector (SQLite and, separately, Postgres via `pqcscan[fleet-pg]`) and enroll at least 30 real or VM hosts across Linux, Windows (via `packaging/fleet/windows-task.ps1`, run as shipped) and one IBM i export. Run daily `agent --once` for seven days. Report from collector logs and the DB: ingest success rate, duplicates, 429/503 counts, spool depth per host, drift rows per host per day, prune counts. Any number above zero that FLEET.md does not predict is a finding.
2. **Detection accuracy.** Build a labelled corpus (certs, keys, TLS endpoints, source snippets, container images) with known expected findings. Run the agent against it. Publish per-probe-family precision and recall as a table in `docs/`, with the corpus hash and the exact command. Fix probes under 0.9 precision or recall or document why not.
3. **Load.** Use k6 or locust to post real bundles from 500 simulated hosts concurrently. Report p50/p95 ingest latency and error rate on SQLite and Postgres against the spec target (p95 < 2 s). Check the scripts and result artefacts into `benchmark/fleet/`.
4. **Threat model.** Write one STRIDE table over enroll, ingest, export and the agent state dir. For every abuse case add a test or a fuzz target (`hypothesis` on `load_bundle`, `parity_key`, label parsing). Record residual risks with owners.
5. **Bake-off.** Install at least two competing scanners (pick from the scorecard in the gap-analysis doc) and run them on the same three images. Normalise exports to one schema and publish a finding-level diff, naming what each tool finds that pqcscan misses.
6. **Acceptance.** For the RFQ prospect: reconcile the fleet CBOM from their hosts against their own asset inventory and produce a discrepancy list for their security team to sign off.

Deliverables: the measurements and artefacts above committed to the repo under `docs/` and `benchmark/`, CI jobs for the Windows installer (Pester, Server 2019 and Windows 11) and Postgres, and a one-page summary stating which claims in `docs/FLEET.md` are now evidenced and which remain assertions. No release tag until items 1–4 pass.

## Environment constraints (what this campaign can and cannot do here)

| Item | Here | Consequence |
|---|---|---|
| 1 Soak | One Linux box (8 cores, 31 GB), Docker, no Windows/IBM i hosts, no 7 days | **Simulated** soak: N agent state dirs with distinct machine ids on this host, minute-scale intervals, injected faults; same metrics; labelled as simulation. Real soak needs user-provided hosts and is scripted so it can be re-run on them. |
| 2 Accuracy | Existing harness `benchmark/run_benchmark.py` (41 offline cases, precision gate 1.0) | Extend with certs/keys/TLS endpoints (local TLS servers)/source/container-image cases and per-family reporting. |
| 3 Load | `locust` installable; Postgres via `docker run postgres:16-alpine` | Doable as specified. |
| 4 Threat model | `hypothesis` installable | Doable as specified. |
| 5 Bake-off | No cargo/java; Docker available; network open | Build Rust tools (anvilsecure/pqcscan, QuantaSeek) in `rust:1-slim` containers; Java tools only if a published image exists. |
| 6 Acceptance | No prospect hosts or inventory | Ship the reconciliation script and sign-off template; the run is blocked on prospect data. |
| CI Windows | GitHub offers `windows-2022`/`windows-latest`; Server 2019 runners retired | Pester job on `windows-2022` and `windows-latest`. |
| Postgres CI | GitHub `services:` container | Doable. |

## Global constraints
- No new product features; new code lives under `benchmark/`, `tests/`, `docs/`, `.github/`, plus a `verify` optional-dependency group in `pyproject.toml` (`hypothesis`, `locust`, `psycopg[binary]`).
- Python >= 3.11; line length 120; ruff + mypy clean on `src` (benchmark scripts ruff-clean).
- Every artefact names the exact command that produced it and the git commit it ran on.
- Commit trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
