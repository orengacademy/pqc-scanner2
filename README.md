# pqcscan

Post-Quantum Cryptography (PQC) readiness scanner. Single Python process. Bundled web UI + headless CLI. Runs locally on Linux, Windows, macOS.

> **Status: 109 / 102 probes shipped — see [docs/STATUS.md](docs/STATUS.md).** Plans A+B+C+D+E+G are all done: asyncio runner, FastAPI daemon + SSE, click CLI, 9-page Jinja+HTMX web UI with EN/MS toggle, SQLite store with baselines + scan diff, CycloneDX 1.6 CBOM, PDF (technical + executive) + XLSX (BUKUKERJA template + generic) renderers, and a 10-framework YAML-driven compliance engine. Only Plan F (PyInstaller packaging) and a real `cve.osv_offline` snapshot remain.
> See `docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md` for the full design.

## Install (development)

```bash
git clone https://github.com/orengacademy/pqc-scanner2 pqcscan
cd pqcscan
pip install -e ".[dev]"
```

Requirements: Python 3.11+. Optional: `openssl` binary on PATH (used by some tests for cert generation).

## Quickstart

```bash
# Start the daemon (web UI on 127.0.0.1:8765 by default).
pqcscan daemon &

# Trigger a scan from the CLI.
pqcscan scan --json
# -> {"scan_id": 1, "finding_count": 12, "high_or_crit_count": 3, "db": "..."}

# List scans.
pqcscan scans

# Export the canonical CBOM (CycloneDX 1.6).
pqcscan export --scan 1 --format cbom -o cbom.json

# Or just visit the UI.
xdg-open http://127.0.0.1:8765
```

## CLI

```
pqcscan version                              # print version
pqcscan daemon [--port 8765] [--bind ...]    # start daemon + web UI
pqcscan scan [--json] [--watch]              # one-shot in-process scan
pqcscan scans                                # list past scans
pqcscan status --id N                        # one scan's status
pqcscan export --scan N --format cbom -o ... # export CycloneDX 1.6
```

Exit codes:
- `0` — scan completed; nothing high/crit.
- `1` — scan completed; high or crit findings present.
- `2` — scan failed.
- `3` — invalid arguments.

## Probe coverage

109 probes registered across all families (host crypto, filesystem, network/TLS/STARTTLS/binary protocols, SBOM, source code, VPN, storage at-rest, container/k8s, app config, signing, DNS/email/web auth, DB-TDE, message-queue brokers, hardware crypto, plus 15 FOSS-tool/VA wrappers around Syft, Grype, testssl, sslyze, nmap, pip-audit, npm-audit, govulncheck, cargo-audit, trivy, lynis, bandit, gitleaks, semgrep, OSV-stub).

```bash
PYTHONPATH=src python3.11 -c \
  "from pqcscan.probes._registry import default_registry; \
   reg = default_registry(); \
   print(f'{len(reg.ids())} probes:'); \
   [print(f'  {p.id} ({p.family.name})') for p in reg.all()]"
```

Family-by-family breakdown is in [`docs/STATUS.md` §2](docs/STATUS.md#2-whats-shipped).

## Tests

```bash
pytest -q --cov=pqcscan --cov-report=term-missing
```

## Build a single-file binary

PyInstaller produces a self-contained `pqcscan` binary that embeds Python, dependencies, web UI templates, framework YAMLs, and the probe registry — no Python install required on the target host.

```bash
pip install -e ".[build]"   # installs pyinstaller>=6
bash scripts/build-binary.sh
./dist/pqcscan --help
```

Output: `dist/pqcscan` (Linux/macOS) or `dist/pqcscan.exe` (Windows). Build artifacts live under `build/pqcscan-work/` and are gitignored. The spec file at [`build/pyinstaller.spec`](build/pyinstaller.spec) is committed and stays in sync with the registry — new probes get picked up automatically via globbing.

Cross-OS CI matrix builds (release artifacts for Linux + macOS + Windows) are tracked separately in Plan F batch 2.

## Tech stack

Python 3.11, FastAPI 0.136, uvicorn, SQLAlchemy 2.0, Jinja2 + HTMX 1.9 (vendored), click, pydantic v2, loguru, cryptography 47, cyclonedx-python-lib 7.6+. All FOSS.

## Malaysia compliance

Probe `framework_tags` already include `bukukerja:*` and `mykripto:*`; the YAML-driven compliance engine that maps findings to MyKripto's Migration Framework, NACSA Arahan KE No. 9, and 6 international frameworks lands in Plan C. See `docs/references/malaysia-pqc.md` for source URLs.

## Licence

MIT (with caveat tracked in the design spec around scapy GPL-2 — not yet a dependency in the MVP).
