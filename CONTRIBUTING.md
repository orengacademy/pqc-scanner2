# Contributing to pqcscan

Thanks for your interest. pqcscan is a Post-Quantum Cryptography readiness
scanner; the goal is **broad, FOSS, offline-capable** PQC + CVE coverage.

## Quick links

- **Bug reports:** [open an issue](https://github.com/orengacademy/pqc-scanner2/issues/new?template=bug_report.md).
- **Feature requests:** [open an issue](https://github.com/orengacademy/pqc-scanner2/issues/new?template=feature_request.md).
- **Security issues:** see [`SECURITY.md`](SECURITY.md). **Do not** file a
  public issue for a vulnerability.
- **Design spec:** [`docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md`](docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md).
- **Resume guide / project state:** [`docs/STATUS.md`](docs/STATUS.md).

## Development setup

```bash
git clone https://github.com/orengacademy/pqc-scanner2 pqcscan
cd pqcscan
pip install -e ".[dev]"
pytest -q
```

Requirements: Python 3.11+. Optional: `openssl` binary on PATH (used by
some tests for cert generation).

## Project layout

```
src/pqcscan/
├── core/         types, alg classifier
├── runner/       async runner, capabilities, event bus
├── store/        SQLite schema + Repo
├── probes/       177 probes; one file per probe; _registry.py wires them up
├── compliance/   engine + framework YAMLs
├── renderers/    PDF + XLSX
├── cbom/         CycloneDX 1.6 builder
├── ui/           Jinja templates + i18n + routes
├── daemon/       FastAPI app + SSE
├── cli/          click subcommands
└── util/         paths, offline_pack
docs/             design spec, plans, references, STATUS.md
tests/{unit,integration}/   pytest suites
build/pyinstaller.spec      cross-OS binary spec
scripts/                    build-binary, fetch-offline-tools, fetch-osv-snapshot
.github/workflows/          ci.yml (lint+type+test) · release.yml (tag build)
```

## How to add a new probe

1. Create `src/pqcscan/probes/<family>_<name>.py`. Follow the shape of an
   existing probe in the same family (e.g. `app_jwt_env_alg.py` for a
   regex-over-config probe, `net_tls_https.py` for a network probe).
2. Subclass `pqcscan.probes._base.Probe`. Set `id`, `family`,
   `framework_tags` (e.g. `("nist-ir-8547:tls", "bukukerja:tls",
   "mykripto:tls")`). Implement `applies(ctx) -> bool` and
   `run(ctx, emit) -> None`.
3. Emit `Finding(probe_id, algorithm, classification, severity, title,
   evidence)`. Use `pqcscan.core.alg.classify(normalise(...))` to convert
   an algorithm name to a `Classification` per the spec's Appendix B
   threat model.
4. Register the probe in `src/pqcscan/probes/_registry.py:default_registry()`.
5. Write tests in `tests/unit/test_probe_<your_probe>.py`. Cover: metadata
   round-trip (id/family), the happy path, and any edge cases that produce
   different classifications.
6. Run `pytest -q tests/unit/test_probe_<your_probe>.py` and ensure green.
7. If your probe wraps a FOSS binary, **use `resolve_or_none(self.X_bin,
   "name")`** from `pqcscan.util.offline_pack` rather than `shutil.which`
   so the offline pack and `PQCSCAN_OFFLINE_PACK` env var work.

## How to add a compliance framework

1. Drop a YAML at `src/pqcscan/compliance/frameworks/<slug>.yaml`. Schema:
   ```yaml
   framework: <slug>
   title: <human-readable name>
   rules:
     - match: { classification: sangat-tinggi }
       clause: <FRAMEWORK>:<clause-id>
       verdict: non-compliant
       note: "..."
   ```
2. Probes get mapped via their `framework_tags`, so add a
   `<slug>:<concern>` tag to relevant probes if you want them automatically
   linked.
3. Add a unit test in `tests/unit/test_compliance_engine.py` that exercises
   at least one of the framework's rules.

**Zero code changes** are needed — the engine is YAML-driven.

## Coding conventions

- **Python 3.11+.** `from __future__ import annotations` is implicit
  everywhere; no need to add it manually for new files but doing so is fine.
- **Async I/O for networked probes** (TLS handshakes, port scans, etc.).
- **Sync I/O for filesystem probes** is OK; pytest doesn't require async
  for sync fixtures.
- **Tests are mandatory** for new behaviour. Use `tmp_path` + synthetic
  fixtures rather than network or real-host data.
- **No mocks for SQLite or HTTP**; use the real `Repo` and
  `fastapi.testclient.TestClient`.
- **Keep findings actionable.** Probe titles should name the file/path/host
  so operators know what to fix.

## Lint + type-check

```bash
ruff check src/ tests/
mypy src/pqcscan
```

The `ci.yml` workflow runs both on every push to `main` and on every PR.

## Tests

```bash
pytest -q                           # full suite
pytest -q tests/unit                # unit only
pytest -q tests/integration         # integration (TestClient + SSE)
pytest -q --cov=pqcscan             # with coverage
```

End-to-end smoke test against a real OSV snapshot:

```bash
bash scripts/fetch-osv-snapshot.sh PyPI    # ~22 MB
PYTHONPATH=src python3.11 -c "
import asyncio
from pathlib import Path
from pqcscan.probes._base import ScanContext
from pqcscan.probes.cve_osv_offline import CveOsvOffline
p = CveOsvOffline(snapshot_path=Path('var/osv-snapshot.jsonl'),
                  roots=[Path('/srv'), Path('/opt')])
ctx = ScanContext(scan_id=1, mode='user', available_capabilities=set())
found = []
asyncio.run(p.run(ctx, emit=lambda f: found.append(f)))
print(f'{len(found)} findings')
"
```

## Pull requests

1. Branch off `main` with a descriptive name: `feat/<probe-id>`,
   `fix/<area>-<short>`, `docs/<area>`.
2. Make the change. Add tests. Run `ruff check`, `mypy`, and `pytest`.
3. Commit using imperative summaries. Conventional-commits prefixes are
   welcome but not required (`feat:`, `fix:`, `docs:`, `chore:`,
   `refactor:`).
4. Open the PR against `main`. CI must be green before merge.
5. Update [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]` if your
   change is user-facing.

## Releasing (maintainers)

```bash
git tag v0.X.0
git push origin v0.X.0
```

The `.github/workflows/release.yml` matrix builds Linux x86_64, macOS arm64,
and Windows x86_64 binaries via PyInstaller and attaches them to the
GitHub Release with auto-generated notes. Maintainers should:

- Update `CHANGELOG.md`: rename `[Unreleased]` → `[v0.X.0] — YYYY-MM-DD` and
  add a fresh `[Unreleased]` section.
- Bump the version in `pyproject.toml` and `src/pqcscan/__init__.py`.
- Tag and push.

## Code of conduct

Be kind. Assume good faith. No harassment, no political flame wars. The
project welcomes contributors regardless of background.

## Licence

By submitting a contribution, you agree that your contribution will be
licensed under the [MIT License](LICENSE).
