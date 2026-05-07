# pqcscan v2 — Project Status & Resume Guide

| | |
|---|---|
| **Date** | 2026-05-07 |
| **Branch / commit** | `plan-h` (Plan H.1 trim + Plan H.2 UDP+DTLS) |
| **Version** | `0.3.0` |
| **Probes** | 106 / 106 registered (Plan H.1 + H.2 + H.3a OT TCP family) |
| **Tests** | 321 passed across unit + integration suites (Python 3.11) |
| **Status** | Plans A+B+C+D+E+F+G shipped; Plan H.1 trim + Plan H.2 (UDP scan + DTLS helper) closed; Plan H.3 (OT/ICS family) follows |

## 1. TL;DR

The full design-doc target is shipped:

- **Plan A** — MVP foundation (core types, SQLite store, async runner + event bus, probe ABC + registry, FastAPI daemon + SSE, click CLI, Jinja+HTMX web UI, CycloneDX 1.6 CBOM, util).
- **Plan B (batches 1–15)** — 92 host/filesystem/network/SBOM/VPN/storage/container/k8s/app/sign/DNS/email/web/code/binary-protocol probes.
- **FOSS-tools + FOSS-VA add-ons** — Syft, Grype, Semgrep, OSV, testssl, sslyze, nmap, pip-audit, npm-audit, govulncheck, cargo-audit, trivy, lynis, bandit, gitleaks (15 wrappers).
- **Plan C** — Compliance engine + 10 framework YAMLs (BUKUKERJA, NIST IR 8547, NIST SP 800-227, CNSA 2.0, BSI TR-02102-1, ANSSI PQC, MAS Notice 655, ENISA PQC, MyKripto, NACSA Arahan KE No. 9).
- **Plan D** — Renderers: PDF technical, PDF executive, XLSX BUKUKERJA, XLSX generic.
- **Plan E (batches 1–4)** — Frameworks page, Probes page, Baselines + scan-vs-baseline diff, EN/MS i18n toggle, Settings page, Mark-as-baseline UX.
- **Plan G (batches 1–3)** — DB-TDE (4 probes), MQ brokers (4 probes), hardware crypto (3 probes) — all from spec §13.1 deferral.
- **Plan F (batches 1–3)** — `build/pyinstaller.spec` for self-contained binary builds, `scripts/build-binary.sh`, GitHub Actions release matrix (Linux/macOS/Windows on tag push, auto-attached release assets), `pqcscan.util.offline_pack.resolve_tool()` runtime tool resolver (env override → MEIPASS bundle → PATH), `scripts/fetch-offline-tools.sh` to stage Syft+Grype, 3 reference probe migrations (`sbom_syft`, `cve_grype`, `cve_trivy_fs`).
- **B17 — Real OSV.dev offline matcher** across **10 ecosystems / 12 lockfile formats**: PyPI (`requirements.txt`, `Pipfile.lock`, `poetry.lock`), npm (`package-lock.json` v6 + v7+), crates.io (`Cargo.lock`), Go (`go.sum`), Packagist (`composer.lock`), RubyGems (`Gemfile.lock`), NuGet (`packages.lock.json`), Hex (`mix.lock`), Pub (`pubspec.lock`), Maven (`gradle.lockfile`). Resolution path: `snapshot_path` constructor arg → `$PQCSCAN_OSV_SNAPSHOT` env → `/var/lib/pqcscan/osv-snapshot.jsonl`.

110 probes registered; SQLite store; web UI at all 9 spec'd pages with EN/MS toggle; PDF/XLSX/CBOM exports; 10 compliance frameworks all evaluated against findings; cross-OS PyInstaller binary build pipeline; offline-pack framework with broad-ecosystem CVE matching.

## 2. What's shipped

### Foundations (Plan A)

| Layer | Path | Notes |
|---|---|---|
| Core types & PQC classifier | `src/pqcscan/core/{types,alg}.py` | Capability/ProbeFamily/Classification/Severity enums; Finding/Component dataclasses; classify() per spec Appendix B |
| SQLite store | `src/pqcscan/store/{schema,migrations,repo}.py` | scans, components, findings, graph_edges, framework_views, baselines; `check_same_thread=False`; baseline create + diff helpers |
| Async runner + event bus | `src/pqcscan/runner/*.py` | Probe isolation, per-probe timeout, asyncio.gather per family, Finding/ScanCompleted SSE events |
| Probe ABC + registry | `src/pqcscan/probes/{_base,_registry}.py` | `default_registry()` seeds 110 probes |
| FastAPI daemon + API | `src/pqcscan/daemon/app.py` | health, version, scans, findings, events SSE, baselines, scan diff |
| Web UI | `src/pqcscan/ui/{routes,templates,static,i18n}.py` | 9 pages; EN/MS toggle via `pqcscan_locale` cookie; vanilla forms, no JS deps |
| CycloneDX 1.6 CBOM + PDF/XLSX renderers | `src/pqcscan/{cbom,renderers}/*` | CBOM JSON, PDF (technical/executive), XLSX (BUKUKERJA template + generic) |
| Compliance engine | `src/pqcscan/compliance/{engine,frameworks/*.yaml}` | YAML-driven; 10 frameworks |
| Click CLI | `src/pqcscan/cli/*.py` | `scan, scans, status, daemon, export` subcommands |

### Probes — 98 total

| Family | Count |
|---|---:|
| HOST | 6 |
| FILESYSTEM | 6 |
| NETWORK (TLS direct + STARTTLS + DB TLS + binary protocols) | ~30 |
| SBOM | 12 |
| CODE | 7 |
| VPN | 3 |
| STORAGE (incl. Plan G db-tde + MQ + hw) | 16 |
| CONTAINER & K8S | 6 |
| APP | 5 |
| SIGN | 5 |
| DNS_EMAIL + WEB | 5 |
| AUX + PQC_META | 3 |
| SECRETS | 1 |
| FOSS-tools + FOSS-VA wrappers | ~15 |

Use `PYTHONPATH=src python3.11 -c "from pqcscan.probes._registry import default_registry; print(len(default_registry().ids()))"` to confirm at any time.

### Web UI pages (all 9 from spec)

`/` Dashboard · `/scans` Scans list · `/scans/{id}` Scan detail (with mark-as-baseline form) · `/frameworks` Frameworks list · `/frameworks/{slug}` Framework detail · `/probes` Probes by family · `/baselines` Baselines list · `/baselines/diff` Scan-vs-baseline diff · `/settings` Settings.

EN/MS i18n toggle in nav writes a 1-year cookie; `_render()` injects `t()` callable into every template context.

## 3. What's deferred

| Item | Status | Rationale |
|---|---|---|
| **Plan F batch 4 — Grype-DB snapshot bundling** | Not started | Multi-GB Grype-DB snapshot is a release-pipeline / artifact-storage decision rather than code. Without it, bundled `grype` falls back to its online DB sync on first run. |
| **FOSS-tool probe migrations** | ✅ Done | All 14 FOSS-tool probes (`sbom_syft`, `cve_grype`, `cve_trivy_fs`, `host_lynis`, `secrets_gitleaks`, `cve_pip_audit`, `cve_npm_audit`, `code_semgrep_pqc`, `net_tls_testssl`, `net_tls_sslyze`, `cve_govulncheck`, `cve_cargo_audit`, `code_bandit`, `net_tls_nmap_ssl`) now resolve via `resolve_or_none()` and honour `$PQCSCAN_OFFLINE_PACK` + PyInstaller's bundled `tools/`. |
| **Range-aware PyPI matching** in `cve.osv_offline` | ✅ Done | `requirements.txt` `>=`/`~=`/`<` / multi-clause specifiers are overlap-checked against OSV `affected[].versions` and `affected[].ranges[].events[]` via the `packaging` library. Range-overlap hits are classified Sederhana ("potentially affected"); exact `==` pin hits remain Tinggi ("definitely affected"). |

**Spec §13.1 deferral is fully closed.** Plan F (batches 1–3) and B17 (across 10 ecosystems) are shipped.

## 4. How to resume

```bash
git clone https://github.com/orengacademy/pqc-scanner2 pqc-scanner2
cd pqc-scanner2
sudo apt-get install -y python3.11 python3.11-venv
python3.11 -m ensurepip --upgrade
python3.11 -m pip install --break-system-packages \
    fastapi 'uvicorn[standard]' sqlalchemy jinja2 click pydantic loguru \
    'cryptography>=42' cyclonedx-python-lib httpx python-multipart pyyaml \
    weasyprint openpyxl pytest pytest-asyncio

# Verify everything still passes.
PYTHONPATH=src python3.11 -m pytest -q

# Smoke-run.
PYTHONPATH=src python3.11 -m pqcscan daemon &
xdg-open http://127.0.0.1:8765
```

> The repo lives on a shared `/mnt/hgfs/...` VMware mount in the original sessions — clone to native ext4 for ~5× speedup on pytest.
> `git -c safe.directory='*' …` is needed on the shared mount; not on native ext4.

## 5. Recommended next steps

1. **Cut a release tag** (e.g. `git tag v0.1.0 && git push origin v0.1.0`) — the `release.yml` workflow will produce binaries for Linux x86_64, macOS arm64, and Windows x86_64 and attach them to a GitHub Release with auto-generated notes.
2. **FOSS-tool probe migrations** — propagate `resolve_or_none()` to the 11 remaining FOSS-tool probes listed in §3. Pure mechanical (~3 lines per probe) but unblocks `$PQCSCAN_OFFLINE_PACK` for all of them.
3. **Plan F batch 4 — Grype-DB snapshot bundling.** Decide where to host the snapshot (release artifact vs. a separate CDN) and extend `scripts/fetch-offline-tools.sh` to download it. Then `grype` works fully offline.
4. **Range-aware PyPI matching** in `cve.osv_offline` — pull in the `packaging` lib and treat each `requirements.txt` line's `SpecifierSet` as a constraint to overlap-check against OSV's `affected[].ranges`. Adds ~50 LOC, real-world coverage jumps significantly.
5. **Probe deepening** — current probes are solid but file-scan / regex-heavy. Consider:
   - Expanding `code.ts.*` from regex to real tree-sitter parsing.
   - Deep ASN.1 parsing for the Kerberos AS-REQ probe.
   - More OSV ecosystems (Hackage, OPAM, Conan, CRAN, Swift Packages).

## 6. Pointers

- **Design spec** — [`docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md`](superpowers/specs/2026-04-29-pqcscan-v2-design.md)
- **MVP plan** — [`docs/superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md`](superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md)
- **Malaysia PQC source references** — [`docs/references/malaysia-pqc.md`](references/malaysia-pqc.md)
- **GitHub repo** — https://github.com/orengacademy/pqc-scanner2 (private)
- **README** — [`README.md`](../README.md)

---

_Last updated: 2026-05-04. Update this file at the end of any session that ships meaningful work._
