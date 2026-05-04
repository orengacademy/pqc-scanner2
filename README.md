# pqcscan

Post-Quantum Cryptography (PQC) readiness scanner. Single Python process. Bundled web UI + headless CLI. Runs locally on Linux, Windows, macOS.

> **MVP foundation status (Plan A complete; Plan B at 51 / 102 probes — see [docs/STATUS.md](docs/STATUS.md)).** This release ships the foundation and 7 representative probes (one per family). The full ~95-probe inventory, the 8-framework compliance engine, the PDF/XLSX renderers, baselines/diff, the i18n EN/MS toggle, and PyInstaller cross-OS packaging are tracked in subsequent plans (B–F).
> See `docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md` for the full design and `docs/superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md` for the MVP plan.

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

## Probes shipping in MVP (7 of 102)

| Probe ID | Family | What it does |
|---|---|---|
| `host.openssl.config` | host | Detects activated OpenSSL legacy provider |
| `sbom.os.dpkg` | sbom | Reads `/var/lib/dpkg/status`; emits PURL per package |
| `net.tls.https` | network | Connects to host:port, parses cipher suite + cert key type |
| `fs.cert.x509` | filesystem | Recursive X.509 cert scan; classifies by key alg |
| `code.ts.python` | code | Regex (placeholder for tree-sitter); flags MD5/SHA1 in `.py` |
| `pqc.alg.normaliser` | pqc-meta | Meta-probe placeholder (logic in `core.alg`) |
| `aux.clock.cert_validity` | aux | Records UTC clock at scan time |

The remaining 95 probes are implemented incrementally in Plan B.

## Tests

```bash
pytest -q --cov=pqcscan --cov-report=term-missing
```

## Tech stack

Python 3.11, FastAPI 0.136, uvicorn, SQLAlchemy 2.0, Jinja2 + HTMX 1.9 (vendored), click, pydantic v2, loguru, cryptography 47, cyclonedx-python-lib 7.6+. All FOSS.

## Malaysia compliance

Probe `framework_tags` already include `bukukerja:*` and `mykripto:*`; the YAML-driven compliance engine that maps findings to MyKripto's Migration Framework, NACSA Arahan KE No. 9, and 6 international frameworks lands in Plan C. See `docs/references/malaysia-pqc.md` for source URLs.

## Licence

MIT (with caveat tracked in the design spec around scapy GPL-2 — not yet a dependency in the MVP).
