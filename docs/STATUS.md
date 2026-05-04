# pqcscan v2 — Project Status & Resume Guide

| | |
|---|---|
| **Date** | 2026-05-04 |
| **Branch / commit** | `main @ 6c18d01` (Plan G batch 3) |
| **Version** | `0.1.0` |
| **Probes** | 109 / 102 registered (target hit + spec §13.1 deferral fully closed) |
| **Tests** | ~290+ passed across unit + integration suites (Python 3.11) |
| **Status** | Plans A+B+C+D+E+G all shipped; only Plan F (PyInstaller packaging) and B17 (OSV snapshot) remain |

## 1. TL;DR

The full design-doc target is shipped:

- **Plan A** — MVP foundation (core types, SQLite store, async runner + event bus, probe ABC + registry, FastAPI daemon + SSE, click CLI, Jinja+HTMX web UI, CycloneDX 1.6 CBOM, util).
- **Plan B (batches 1–15)** — 92 host/filesystem/network/SBOM/VPN/storage/container/k8s/app/sign/DNS/email/web/code/binary-protocol probes.
- **FOSS-tools + FOSS-VA add-ons** — Syft, Grype, Semgrep, OSV, testssl, sslyze, nmap, pip-audit, npm-audit, govulncheck, cargo-audit, trivy, lynis, bandit, gitleaks (15 wrappers).
- **Plan C** — Compliance engine + 10 framework YAMLs (BUKUKERJA, NIST IR 8547, NIST SP 800-227, CNSA 2.0, BSI TR-02102-1, ANSSI PQC, MAS Notice 655, ENISA PQC, MyKripto, NACSA Arahan KE No. 9).
- **Plan D** — Renderers: PDF technical, PDF executive, XLSX BUKUKERJA, XLSX generic.
- **Plan E (batches 1–4)** — Frameworks page, Probes page, Baselines + scan-vs-baseline diff, EN/MS i18n toggle, Settings page, Mark-as-baseline UX.
- **Plan G (batches 1–3)** — DB-TDE (4 probes), MQ brokers (4 probes), hardware crypto (3 probes) — all from spec §13.1 deferral.

109 probes registered; SQLite store; web UI at all 9 spec'd pages with EN/MS toggle; PDF/XLSX/CBOM exports; 10 compliance frameworks all evaluated against findings.

## 2. What's shipped

### Foundations (Plan A)

| Layer | Path | Notes |
|---|---|---|
| Core types & PQC classifier | `src/pqcscan/core/{types,alg}.py` | Capability/ProbeFamily/Classification/Severity enums; Finding/Component dataclasses; classify() per spec Appendix B |
| SQLite store | `src/pqcscan/store/{schema,migrations,repo}.py` | scans, components, findings, graph_edges, framework_views, baselines; `check_same_thread=False`; baseline create + diff helpers |
| Async runner + event bus | `src/pqcscan/runner/*.py` | Probe isolation, per-probe timeout, asyncio.gather per family, Finding/ScanCompleted SSE events |
| Probe ABC + registry | `src/pqcscan/probes/{_base,_registry}.py` | `default_registry()` seeds 109 probes |
| FastAPI daemon + API | `src/pqcscan/daemon/app.py` | health, version, scans, findings, events SSE, baselines, scan diff |
| Web UI | `src/pqcscan/ui/{routes,templates,static,i18n}.py` | 9 pages; EN/MS toggle via `pqcscan_locale` cookie; vanilla forms, no JS deps |
| CycloneDX 1.6 CBOM + PDF/XLSX renderers | `src/pqcscan/{cbom,renderers}/*` | CBOM JSON, PDF (technical/executive), XLSX (BUKUKERJA template + generic) |
| Compliance engine | `src/pqcscan/compliance/{engine,frameworks/*.yaml}` | YAML-driven; 10 frameworks |
| Click CLI | `src/pqcscan/cli/*.py` | `scan, scans, status, daemon, export` subcommands |

### Probes — 109 total

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
| **Plan F — PyInstaller packaging + offline pack** | Not started | Significant CI work; ships when distribution is needed. |
| **B17 — `cve.osv_offline` real DB snapshot** | Stub | Needs either OSV.dev mirror bundling (multi-GB; gated on Plan F) or runner-level SBOM-output sharing (architectural). Existing CVE coverage via `cve.grype` / `cve.pip_audit` / `cve.npm_audit` / `cve.govulncheck` / `cve.cargo_audit` / `cve.trivy_fs` is comprehensive. |

That's it. **Spec §13.1 deferral is fully closed.**

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

1. **Plan F** — only remaining roadmap item. Cross-OS PyInstaller binaries + offline pack (bundles Syft + Grype + Semgrep + OSV snapshot).
2. **B17 follow-up** — once Plan F lands, drop the OSV snapshot in place and replace `cve.osv_offline.py` body with a real matcher.
3. **Probe deepening** — current probes are solid but mostly file-scan / regex. Consider:
   - Expanding `code.ts.*` from regex to real tree-sitter parsing.
   - Adding ASN.1 deep parsing for the Kerberos AS-REQ probe.
   - Bundling Grype-DB snapshot for `cve.grype`'s offline mode.

## 6. Pointers

- **Design spec** — [`docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md`](superpowers/specs/2026-04-29-pqcscan-v2-design.md)
- **MVP plan** — [`docs/superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md`](superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md)
- **Malaysia PQC source references** — [`docs/references/malaysia-pqc.md`](references/malaysia-pqc.md)
- **GitHub repo** — https://github.com/orengacademy/pqc-scanner2 (private)
- **README** — [`README.md`](../README.md)

---

_Last updated: 2026-05-04. Update this file at the end of any session that ships meaningful work._
