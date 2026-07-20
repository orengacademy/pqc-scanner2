# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — full bilingual web
- **Complete EN/MS coverage of the web UI.** The dashboard body, scan-detail
  page, and scans list are now fully translated into Bahasa Melayu, joining the
  already-localised nav/settings/frameworks/probes/baselines pages. Every
  user-visible string — page headings, the "How to read this page" band
  legend, the run-a-scan form, organisational-readiness tiles, crypto-surface
  breakdown, NACSA migration-phase notes, export cards, band filter chips,
  finding remediation chips, table headers, and the footer tagline / theme
  aria-label — now flips with the `pqcscan_locale` cookie. Technical acronyms
  (PQC, TLS, ML-KEM, SARIF, CBOM, HNDL, NIST, NACSA, SSE) are kept verbatim in
  both languages.

## [0.7.5] — 2026-07-20

### Added — findings UX
- **Inline remediation on every finding.** The scan-detail rows now render the
  PQC migration guidance produced by the classifier enrichment — a green
  "→ migrate to ML-KEM-768 (FIPS 203)" chip, a deadline chip, and an **HNDL**
  badge for harvest-now-decrypt-later exposure. What the scanner *recommends*
  is now visible in the UI, not just in the SARIF/report exports.
- **Findings text filter** — a search box narrows the list by probe id,
  algorithm, or title, client-side, composing with the band chips.
- **Live progress** — while a scan runs, a status pill consumes the SSE stream
  to show a running finding count + current stage, and the page reloads on
  completion.

## [0.7.4] — 2026-07-20

### Changed — web UI design system
- **Self-contained fonts.** Removed the Google Fonts network `<link>` — the
  web UI no longer makes any external request, so the frozen binary and
  air-gapped hosts render identically (and it's CSP-clean). Mono-forward
  "audit tool" identity preserved via a system-font stack.
- **Light + dark theme.** New `data-theme` system with a nav toggle
  (sun/moon), persisted to `localStorage` and defaulting to the OS
  preference; theme is applied before first paint (no flash). A semantic
  token layer (`--page-bg`, `--surface`, `--border`, `--text`, `--accent`…)
  drives the chrome, and the content templates' Tailwind utilities are
  remapped for light mode. Amber accent darkens to amber-600/700 on white
  for contrast.
- **Dynamic version** in the nav + footer (was hardcoded `v0.1.0`), sourced
  from `pqcscan.__version__` via a Jinja global.


## [0.7.3] — 2026-07-20

### Added — reporting & integration
- **SARIF 2.1.0 renderer** (`renderers/sarif.py`, export slug `sarif`, API
  `/api/scans/{id}/export/sarif`). Each probe becomes a SARIF `rule`; each
  finding a `result` with the correct `level` (crit/high→error, med→warning,
  low/info→note), a GitHub `security-severity` score, the PQC migration target
  + deadline in the message and properties, and a `physicalLocation` when a
  probe recorded an on-disk path. Unlocks GitHub Code Scanning.
- **QRAMM compliance framework** (`compliance/frameworks/qramm.yaml`) — the
  Quantum Readiness Assurance Maturity Model, mapping the cryptographic-posture
  dimension onto compliant / at-risk / non-compliant verdicts (11 frameworks
  total). Bundled into the frozen binary automatically.

## [0.7.2] — 2026-07-20

### Added — coverage wave (reverse-proxy / mesh + long-tail host posture)
- **`fs.conf.haproxy`** — HAProxy `ssl-default-bind-ciphers(uites)`, `ssl-min-ver`,
  and force/no-tls options.
- **`fs.conf.envoy`** — Envoy `tls_params` (min/max version, `cipher_suites`,
  `ecdh_curves`) across YAML/JSON.
- **`fs.conf.traefik`** — Traefik `tls.options` (`minVersion`, `cipherSuites`,
  `curvePreferences`) across YAML/TOML.
- **`fs.conf.caddy`** — Caddyfile / Caddy-JSON explicit TLS weakenings
  (`protocols`, `cipher_suites`, `curves`, `key_type`).
- **`host.rng.config`** — kernel entropy pool + hardware-RNG / entropy-daemon
  posture (weak RNG → weak keys).
- **`host.pam.hashing`** — system password-hash algorithm (`ENCRYPT_METHOD`,
  `pam_unix`, `/etc/shadow` prefixes); flags DES/MD5 crypt.
- **`host.ssh.moduli`** — flags `/etc/ssh/moduli` DH-GEX groups < 3072 bits.

## [0.7.1] — 2026-07-20

### Added
- **Target/domain scanning.** Scans can now be pointed at real endpoints, not
  just the local host. `pqcscan scan --target host[:port]` activates the
  TLS/STARTTLS probe family; `--path` (repeatable) activates the
  certificate/key/code probes; `--ot host:port[:proto]` (repeatable) activates
  the OT/ICS probes. The runner threads `scan_paths`/`server_target`/
  `ot_targets` into every `ScanContext`, so the ~30 network probes and OT
  family — previously dormant because nothing ever set a target — now fire.
- `POST /api/scans` accepts an optional JSON body
  (`{"target": ..., "paths": [...], "ot_targets": [...]}`).
- Web UI: a "Run a scan" form on the dashboard (`POST /scans/new`) triggers a
  scan against a pasted host/paths and deep-links to the scan-detail page.
- `pqcscan/runner/targets.py` centralises target parsing (URL-scheme stripping,
  OT default-port table) so CLI, API, and web form interpret targets identically.

## [0.7.0] — 2026-07-20

### Added
- **Classifier hardening (`core/alg.py`).** OID table extended with the NIST
  FIPS 203/204/205 arcs (ML-KEM, ML-DSA, SLH-DSA — both standard and legacy
  OQS OIDs), RSASSA-PSS, ECDSA-SHA224/512, Ed448, DSA variants, and bare hash
  OIDs. SLH-DSA / Falcon / composite-hybrid names now classify PQC-ready; RSA
  signature-alg names (`RSA-SHA256`, `RSA-PSS`) classify TINGGI instead of
  falling through to INFO; AES-128 GCM/CCM is SEDERHANA while AES-128-CBC is
  TINGGI; ChaCha20 and AES-192/256 are RENDAH.
- **Harvest-now-decrypt-later + deadline logic.** `hndl_exposed()`,
  `is_key_establishment()`, and `migration_deadline()` score key-establishment
  primitives against the CNSA 2.0 calendar (2030 for HNDL key establishment,
  2035 for full transition).
- **Structured remediation (`core/remediation.py`).** Every finding is now
  centrally enriched (in the runner) with a typed PQC-replacement descriptor —
  target algorithm, FIPS standard, migration deadline, and HNDL rationale
  (RSA/DH/ECDH → ML-KEM-768 hybrid; RSA/ECDSA/EdDSA → ML-DSA-65; AES-128 →
  AES-256). Probe-authored remediation snippets are preserved.
- **Public-key health (`core/keyhealth.py`).** ROCA (CVE-2017-15361)
  fingerprint detection and small-modulus flagging over public moduli only —
  catches keys broken *today*, independent of the quantum threat.

## [0.6.10] — 2026-07-20

### Fixed
- Linux release binary now runs on glibc ≥ 2.17 hosts (RHEL / Oracle Linux
  7.9+). Previous releases were built on `ubuntu-latest`, so the bundled
  `libpython3.11.so.1.0` required `GLIBC_2.38` and the binary aborted on OL7
  with `Failed to load Python shared library ... GLIBC_2.38 not found`. The
  Linux build now runs inside a `manylinux2014` (CentOS 7 userland) container
  via `scripts/build-linux-compat.sh`, using a uv-managed CPython 3.11
  (python-build-standalone, glibc 2.17 floor) and only `manylinux2014`-tagged
  wheels; the script smoke-tests the result (`--help`, `version`) on an
  `oraclelinux:7.9` container. `scripts/build-binary.sh` delegates to the
  compat build automatically on Linux x86_64 when docker is available
  (opt out with `PQCSCAN_NO_COMPAT=1`), so CI needed no workflow changes.
  Verified end to end on OL 7.9: daemon boots, `/api/health` returns 200.

## [0.6.9] — 2026-06-22

### Fixed
- Version string is no longer frozen at `0.1.0`. `pqcscan.__version__` is now
  the single source of truth, and `pyproject.toml` reads it via
  `[tool.hatch.version]`, so the wheel metadata, `pqcscan version`, and the
  `/api/health` endpoint all report the real release version — including in the
  PyInstaller frozen binary, which previously self-reported `0.1.0`.

### Added
- `packaging/systemd/pqcscan.service` — hardened systemd unit for the daemon.
- `docs/DEPLOYMENT.md` — production deploy guide (prebuilt binary + systemd,
  privilege trade-off, SSH-tunnel / nginx TLS+auth access, SELinux notes),
  linked from the README.

### Notes
First release candidate. The design-spec target (109 probes, 10 compliance
frameworks, 9 web UI pages, cross-OS binary build) is fully met.

## [0.1.0] — 2026-05-05 (pending tag)

### Added — foundation (Plan A)

- `pqcscan.core` — Capability/ProbeFamily/Classification/Severity enums;
  Finding/Component dataclasses; OID/friendly-name normalisation; classify()
  routing per spec Appendix B.
- `pqcscan.store` — SQLite store with 6 tables (scans, components, findings,
  graph_edges, framework_views, baselines), `check_same_thread=False` for
  cross-thread daemon use.
- `pqcscan.runner` — async runner with per-probe timeout, `asyncio.gather`
  per family, in-memory event bus (Stage/Finding/ScanCompleted events).
- `pqcscan.probes._base` + `_registry` — Probe ABC with id/family/requires/
  framework_tags metadata; `default_registry()` seeds the built-in probes.
- `pqcscan.daemon` — FastAPI daemon + SSE; routes for health/version/scans/
  findings/events/baselines/diff.
- `pqcscan.cli` — click CLI with `version, scan, scans, status, daemon,
  export` subcommands; exit codes 0/1/2/3.
- `pqcscan.ui` — Jinja+HTMX 9-page web UI with EN/MS i18n toggle.
- `pqcscan.cbom` — CycloneDX 1.6 CBOM exporter with crypto-asset components
  and `nistQuantumSecurityLevel` mapping.

### Added — probes (Plan B batches 1–15, Plan G batches 1–3, FOSS-VA suite)

- 109 probes across 14 families: HOST · FILESYSTEM · NETWORK · SBOM · CODE ·
  VPN · STORAGE · CONTAINER+K8S · APP · SIGN · DNS_EMAIL+WEB · AUX+PQC_META
  · SECRETS · FOSS-tool wrappers.
- Plan B batch 15 binary protocols: `net.ssh.handshake`, `net.ike.v1v2`,
  `net.rdp.negotiation`, `net.smb.dialect`, `net.snmp.version`,
  `net.kerberos.asreq`, `net.db.mysql_tls` (CLIENT_SSL handshake parse),
  `net.starttls.ldap` (ASN.1 ExtendedRequest).
- Plan G batch 1 DB-TDE: `db.pg.pgcrypto`, `db.mysql.keyring`, `db.mssql.tde`,
  `db.mongo.encrypted_storage`.
- Plan G batch 2 MQ brokers: `mq.kafka.tls`, `mq.rabbitmq.tls`, `mq.nats.tls`,
  `mq.mqtt.broker`.
- Plan G batch 3 hardware crypto: `hw.tpm.algorithms`, `hw.pkcs11.modules`,
  `hw.smartcard.readers`.
- 15 FOSS-tool / FOSS-VA probe wrappers (Syft, Grype, Semgrep, OSV, testssl,
  sslyze, nmap, pip-audit, npm-audit, govulncheck, cargo-audit, trivy, lynis,
  bandit, gitleaks).

### Added — compliance + reporting (Plans C–D)

- `pqcscan.compliance` — YAML-driven engine; 10 framework rule files:
  BUKUKERJA · NIST IR 8547 · NIST SP 800-227 · CNSA 2.0 · BSI TR-02102-1 ·
  ANSSI PQC · MAS Notice 655 · ENISA PQC · MyKripto · NACSA Arahan KE No. 9.
- `pqcscan.renderers` — PDF technical, PDF executive, XLSX BUKUKERJA template,
  XLSX generic.

### Added — UI features (Plan E batches 1–4)

- `/frameworks`, `/frameworks/{slug}` — bundled framework rule browser.
- `/probes` — registry view grouped by family.
- `/baselines`, `/baselines/diff` — baseline management + scan-vs-baseline
  diff (added/removed/common counts).
- `/settings` — version, Python, platform, privilege mode, DB path,
  capability matrix, probe count, framework count.
- Mark-as-baseline form on the scan-detail page.
- EN/MS i18n toggle (cookie-based, ~40 translation keys per locale).

### Added — distribution (Plan F batches 1–3)

- `build/pyinstaller.spec` — single-file binary spec; bundles UI templates,
  static assets, renderer templates, framework YAMLs, Semgrep rules, and
  (optionally) a `tools/` directory.
- `scripts/build-binary.sh` — wrapper that cleans prior artifacts, runs
  PyInstaller, and smoke-tests the binary with `--help`.
- `.github/workflows/release.yml` — cross-OS release matrix (ubuntu-latest,
  macos-latest, windows-latest); attaches `pqcscan-{linux-x86_64, macos-arm64,
  windows-x86_64.exe}` binaries to the GitHub Release on `v*` tag push.
- `pqcscan.util.offline_pack` — `resolve_tool()` and `resolve_or_none()`
  helpers (env var → MEIPASS → system PATH search order). Wired through
  all 14 FOSS-tool probes.
- `scripts/fetch-offline-tools.sh` — stages Syft + Grype binaries for the
  current platform.

### Added — offline OSV matcher (B17)

- `cve.osv_offline` real implementation, replacing the v0.1.0 stub. Resolves
  snapshot via constructor arg → `$PQCSCAN_OSV_SNAPSHOT` env →
  `/var/lib/pqcscan/osv-snapshot.jsonl` default. Accepts JSONL **or**
  JSON-array snapshot format.
- 12 lockfile parsers across 10 ecosystems: `requirements.txt`, `Pipfile.lock`,
  `poetry.lock` (PyPI), `package-lock.json` v6+v7+ (npm), `Cargo.lock`
  (crates.io), `go.sum` (Go), `composer.lock` (Packagist), `Gemfile.lock`
  (RubyGems), `packages.lock.json` (NuGet), `mix.lock` (Hex), `pubspec.lock`
  (Pub), `gradle.lockfile` (Maven).
- Range-aware PyPI matching via the `packaging` library: `>=`/`~=`/range
  constraints in `requirements.txt` are overlap-checked against OSV
  `affected[].versions` and `affected[].ranges[].events[]`. Range overlaps
  classify as Sederhana ("potentially affected"); exact `==` pins remain
  Tinggi.
- `scripts/fetch-osv-snapshot.sh` — codifies the OSV.dev snapshot
  download + concat-to-JSONL flow.

### Fixed

- `cve.osv_offline` deduplicates per-record (ecosystem, name) keys at
  index-build time. Discovered live against the OSV.dev PyPI snapshot
  (19,220 advisories): records like `urllib3 GHSA-34jh-p97f-mpxf` and
  `django GHSA-qw25-v68c-qjf3` list the same package under multiple
  `affected[]` entries; pre-fix this caused 40 duplicate (path, pkg,
  advisory) findings — now zero. (Commit `28fb7a8`.)
- SMB protocol-id bytes-literal in `net.smb.dialect` switched from
  implicit-string-concat (which Python 3.11 breaks at `b"\x00" * N`
  expressions) to explicit `+` concatenation. (Commit `ce8f584`.)

[Unreleased]: https://github.com/orengacademy/pqc-scanner2/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/orengacademy/pqc-scanner2/releases/tag/v0.1.0
