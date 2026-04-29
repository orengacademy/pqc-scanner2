# pqcscan v2 — Design Spec

- **Date:** 2026-04-29
- **Status:** Draft for review
- **Predecessor:** `pqc_auto_scan.py` (v1, ~50 KB monolithic Python orchestrator). v2 is a fresh codebase — **no source reuse from v1**. v1 stays in the repo for reference.

---

## 1. Goal

Build a Post-Quantum Cryptography (PQC) readiness scanner that:

- Runs locally on any production server (Linux x86_64/arm64, Windows Server, macOS) as a self-contained binary.
- Inventories every cryptographic asset on the host: OS-installed crypto libs, listening services, certificates, keys, config files, source code, application config, signing keyrings, storage encryption, container/Kubernetes layer, DNS/email crypto, and more.
- Classifies each asset against PQC threat models (Shor / Grover) and maps it to multiple compliance frameworks in a single pass.
- Presents results in a **bundled web UI** (localhost-only, real-time SSE-streamed progress) and via a **headless CLI**.
- Exports findings as **CycloneDX 1.6 CBOM (canonical)**, executive PDF, technical PDF, BUKUKERJA XLSX (Malaysian template), and generic XLSX. Dual-language: English / Bahasa Melayu.
- Operates **fully offline** on airgapped servers, with a sneakernet-friendly update pack.
- Is **fully FOSS** (no proprietary dependencies, no commercial-tier features).
- Leaves a clean architectural seam so future remote-scan modes (push-agent, pull-controller, agentless network probe) can be wrapped onto the same internal API without redesign.

## 2. Out of scope (v1)

- Multi-tenant / SaaS deployment, user accounts, RBAC, organisation isolation.
- Authentication / login screen (UI binds to `127.0.0.1` only).
- Remote scanning of any kind (the daemon's HTTP API is the seam; no remote wrappers ship in v1).
- Database-at-rest TDE probes, message-queue / broker probes, hardware crypto probes (TPM / PKCS#11 / smartcard) — **deferred to v2.next**.
- Telemetry / phone-home — none, ever.

## 3. Locked decisions (with rationale)

| Decision | Choice | Rationale |
|---|---|---|
| Deployment model | Local-on-server, single self-hosted box | Simplest scope; matches "execute on any server". |
| Web UI access | Localhost only, no login | OS-level access is the trust boundary; no auth subsystem needed. |
| Check categories | All five (host crypto, SBOM+CVE, network services, filesystem artefacts, source-code CBOM) | Broad coverage matches the v1 surface. |
| Blindspot families included | VPN beyond IKE, storage at rest, container/K8s, app-config crypto, signing & integrity, DNS/email/web auth, hybrid PQC + alg normalisation. | Covers known v1 gaps. |
| Blindspot families deferred | DB-TDE, message queues, hardware crypto. | Trims v1 to ~100 probes; specialised families wait for v2.next. |
| Reporting / ops features | Remediation snippets, scan history & diff, executive summary export, asset attribution | All four locked in. |
| Execution model | Daemon (systemd / Windows Service / launchd) + real-time SSE-streamed UI + headless CLI | Best UX while still allowing cron / `ssh` use without ever opening a browser. |
| OS targets | Linux + Windows + macOS, full cross-platform | "Any server" is a hard constraint. |
| Language / stack | Python 3.11, packaged per OS via PyInstaller `--onefile` | User-selected; trades single-binary portability for runtime familiarity. |
| Privilege model | Hybrid: run as current user; flag root-only checks as `skipped_privilege`; UI banner offers `sudo pqcscan rescan` | Lowest install friction with explicit, visible coverage gaps. |
| External tool bundling | Bundle Syft + Grype + Grype-DB-snapshot + Semgrep-OSS + tree-sitter + liboqs into the PyInstaller artefact (~340 MB). Sneakernet-friendly offline update pack. | Works fully offline on day 1; refresh path exists. |
| Detection paradigm | L1+L2+L3 hybrid: best-of-breed FOSS tools + native Python detectors + new paradigm (probe registry, CycloneDX 1.6 CBOM, findings graph, compliance engine, streaming, differential, pluggable probes) | "Fresh code, design, approach, method" with no artificial exclusions; FOSS-only. |
| Compliance frameworks | All eight: BUKUKERJA, NIST IR 8547, NIST SP 800-227, CNSA 2.0, BSI TR-02102-1, ANSSI PQC, MAS Notice 655, ENISA PQC. Each as a YAML rule file. | Broad export story; user-extensible. |
| Future remote-scan seam | Daemon HTTP+JSON API on `127.0.0.1` is the only contract. Future modes (agent push, hub pull, agentless network probe) all wrap this API without a redesign. | YAGNI for v1; no demolition required later. |
| Frontend stack | Jinja2 templates + HTMX + SSE + vendored Tailwind | No Node toolchain anywhere; SSE matches the one-way live-progress UX exactly. |
| DB location & retention | `/var/lib/pqcscan/pqcscan.db` (Linux), `%PROGRAMDATA%\pqcscan\pqcscan.db` (Windows), `/Library/Application Support/pqcscan/pqcscan.db` (macOS). Retention: last 30 days + all baselines forever. | Sensible defaults; configurable. |
| Localisation | English-default UI; per-browser EN/BM toggle (cookie-based, no auth); CLI `--lang` flag; renderers fully bilingual (BUKUKERJA xlsx remains Malay since it's the source spec). | Broader audience without losing Malay deliverable fidelity. |
| Default scan scope | `pqcscan scan` with no flags runs every applicable probe across the whole host, using config-defined search roots. Flags only **narrow** the default. | Matches user intent — drop and run on any server. |

## 4. System architecture

One Python 3.11 process, packaged as a single PyInstaller binary per OS/arch. The binary wears three hats simultaneously: **CLI** (entry-point dispatcher), **daemon** (asyncio HTTP+SSE server on `127.0.0.1`), **web UI** (Jinja templates served by the same daemon).

### 4.1 Components (single binary)

```
┌────────────── Single binary — pqcscan ───────────────┐
│                                                       │
│  CLI front  ↔  Daemon (asyncio)  ↔  Web UI (Jinja+HTMX) │
│                       │                              │
│                       ▼                              │
│          Probe runner   Event bus   Compliance engine │
│                       │                              │
│                       ▼                              │
│                 Probe registry        Renderers       │
│                       │                              │
│                       ▼                              │
│                 SQLite              Cache dir         │
│                                                       │
│  External FOSS tools (subprocesses / native libs):    │
│  Syft  Grype  Semgrep-OSS  tree-sitter  openssl/ssh   │
│  liboqs-python                                        │
└───────────────────────────────────────────────────────┘
```

Future remote shapes (agent push, hub pull, agentless network probe) are explicitly **not** in v1 — they will wrap the daemon's HTTP API later without changes here.

### 4.2 Data flow during a scan

1. CLI or web UI POSTs to `/api/scans` → daemon creates a `scans` row, returns `id`.
2. Probe runner topologically sorts probes by declared dependencies (`cve.grype` depends on `sbom.os.*`, etc.), respects per-family concurrency caps, applies per-probe timeouts.
3. Each probe runs on the asyncio event loop for I/O work; sync libraries (paramiko, scapy, cryptography) execute on a thread-pool executor.
4. As probes find things, they emit `FindingDiscovered` / `StageStarted` / `StageCompleted` events on an in-memory bus.
5. Two consumers subscribe to the bus:
   - **Storage layer** writes to SQLite (`components`, `findings`, `graph_edges`).
   - **SSE stream** broadcasts to the web UI and to `pqcscan scan --watch`.
6. **Compliance engine** decorates each finding with framework tags as it passes through, writing to `framework_views`.
7. When the runner finishes, the daemon updates `scans.status = 'done'` and emits `ScanCompleted`.
8. Renderers (CBOM JSON, PDFs, XLSX) read SQLite directly when invoked from CLI / UI — they're materialised views, never re-running probes.

### 4.3 Concurrency model

- Single asyncio event loop per daemon process.
- I/O probes (TCP/TLS/SSH/HTTP/etc.) run as native coroutines.
- Sync-library probes wrap calls in `asyncio.to_thread()`.
- Per-family concurrency caps (e.g., max 8 simultaneous TCP probes against `localhost`) prevent thundering-herd against any one service.
- Per-probe timeout, default 30 s, configurable.

## 5. Probe model

### 5.1 Probe interface

```python
class Probe:
    id: str                         # e.g. "host.openssl.config"
    family: ProbeFamily             # Host | Network | Filesystem | Code | Container | ...
    requires: set[Capability]       # Root | NetRaw | DACReadSearch | Kubectl | ContainerRT
    framework_tags: list[str]       # ["nist-ir-8547:RSA", "cnsa2:RSA", "bukukerja:tinggi"]
    enabled_default: bool = True

    async def applies(self, ctx: ScanContext) -> bool:
        """Quick precheck — is this probe relevant on this host?"""
    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        """Do the work; call emit(Finding(...)) for each result."""
```

### 5.2 User-extensible probes

- **Python probes:** drop a `*.py` into `/etc/pqcscan/probes.d/` (Linux paths shown; equivalents on Windows/macOS). Loaded at daemon start.
- **YAML probes:** declarative pattern probes covering ~70% of common cases — file globs + regex + classification tags — without writing Python:

  ```yaml
  id: app.custom.jwt-secret
  family: app-config
  requires: []
  framework_tags: [bukukerja:tinggi, nist-ir-8547:RSA]
  match:
    files:
      - /etc/myapp/*.yaml
      - /opt/myapp/config/*.json
    patterns:
      - regex: 'jwt[._-]?alg.*HS256'
        severity: high
        message: HMAC-SHA256 JWT signing detected
  ```

### 5.3 Built-in probe inventory (v1 — 102 probes across 13 families)

| Family | Count | Notes |
|---|---:|---|
| Host crypto inventory | 10 | OS-installed libs and config |
| SBOM + CVE matching | 15 | dpkg/rpm/apk/pacman/brew/winreg + lang-pkg-managers + Syft fallback + Grype + OSV.dev offline |
| Listening network services | 25 | Bulk of v1 stages 0, 5, 6, 9–15 |
| Filesystem artefacts | 12 | x509/private-keys + nginx/apache/sshd/openssl/postfix/dovecot/bind9/haproxy/envoy/vsftpd configs |
| Source-code CBOM | 7 | Semgrep OSS PQC ruleset + tree-sitter Python/JS/Go/Java/PHP/Rust |
| VPN beyond IKE | 3 | WireGuard, OpenVPN, Tailscale |
| Storage encryption at rest | 5 | LUKS / BitLocker / ZFS / dm-crypt / fscrypt |
| Container & Kubernetes | 6 | Runtime, image SBOM, ingress TLS, secrets types, Helm releases, mesh mTLS |
| App-config crypto | 5 | JWT alg in env, OAuth JWKS, dotenv secrets, Spring properties, nginx JWT validation |
| Signing & integrity | 5 | GPG keyrings, repo signing, Authenticode, git signing, cosign |
| DNS / Email / Web auth | 5 | DNSSEC, DKIM, S/MIME, WebAuthn, system trust roots |
| Hybrid PQC + alg normalisation | 2 | X25519MLKEM768 detection; OQS↔NIST FIPS 203/204/205 alias resolution |
| System auxiliary | 2 | Clock-vs-cert validity, distrusted root list |

Total: 102 probes across 13 families. Full probe IDs are listed in Appendix A.

### 5.4 Probe runner behaviour

- Topological sort by declared `depends_on`.
- Per-family concurrency caps.
- Per-probe timeout (default 30 s).
- **Probe isolation:** a probe crash records a `probe_error` row (severity `info`, classification `error`) and the runner moves on — never aborts the scan.
- In **non-root mode**, any probe whose `requires` contains `Root` is recorded as `skipped_privilege` instead of running. The UI banner counts these and offers a one-click "re-run as root" instruction.

## 6. Data model

### 6.1 SQLite schema

Single `pqcscan.db` per host. Six tables:

| Table | Purpose |
|---|---|
| `scans` | One row per scan run; `mode` = root \| user; `probe_versions` and `tool_versions` JSON; `status` ∈ {running, done, failed}; `label` (NULL or user-given). |
| `components` | Every discovered asset (OS pkg, lib, service, cert, key, file, app, container) keyed by **PURL**. |
| `findings` | Every detected crypto fact. Normalised `algorithm` field (collapses OID, friendly name, library name). `classification` ∈ {sangat-tinggi, tinggi, sederhana, rendah, pqc-ready, info, error}. Structured `evidence` and `remediation` JSON. |
| `graph_edges` | The dependency graph: `cert → cipher-suite → service → process → package → CVE`. Edge types: `uses`, `depends_on`, `signed_by`, `terminates_tls_for`, `contains_key`, `owned_by`. |
| `framework_views` | Finding × framework join. One finding can map to many frameworks at once. Compliance engine writes here. |
| `baselines` | Labelled snapshots for differential scans. |

Indices:

- `scans (started_at)`, `scans (status)`
- `components (scan_id, type)`, `components (purl)`
- `findings (scan_id, classification)`, `findings (algorithm)`, `findings (component_id)`
- `graph_edges (scan_id, src_id)`, `graph_edges (scan_id, edge_type)`
- `framework_views (finding_id)`, `framework_views (framework, verdict)`

Retention: last 30 days of scans + all baseline-tagged scans forever. Daily cleanup task runs at daemon startup and at 03:00 local time.

### 6.2 CycloneDX 1.6 CBOM (canonical export)

Every finding maps to a `cryptographic-asset` component with `cryptoProperties.assetType` ∈ {algorithm, certificate, key, protocol, related-crypto-material}. The `graph_edges` table populates the CBOM's `dependencies` array. The host itself is the top-level `metadata.component` (`type: device`).

Validator: `cyclonedx-python-lib` (Apache-2.0) — round-trip every emitted CBOM through schema validation in CI.

### 6.3 Renderers read SQLite, never the CBOM

PDF and XLSX renderers query SQLite + `framework_views` directly. Adding a new report format never requires regenerating the CBOM. The CBOM is one of five renderers, not the source of truth for the others.

## 7. Web UI

### 7.1 Pages (v1)

| Path | Purpose |
|---|---|
| `/` (Dashboard) | Latest scan headline numbers, framework compliance chips, "Scan now" button, scan-history sparkline. |
| `/scans` | All scans table — date, mode, finding count, status. |
| `/scans/<id>` | Live during scan: progress + streaming findings. After: summary + finding tree by family. |
| `/findings/<id>` | Single finding: evidence excerpt, normalised algorithm, framework verdicts, remediation snippet. |
| `/frameworks/<name>` | Pick a framework, see all its mapped findings with deadlines. |
| `/baselines` | Create / label / pick baseline; run diff against any scan. |
| `/probes` | All probes, family, enabled/disabled, last-run status, framework tags. Toggle from UI. |
| `/exports` | Generate & download CBOM JSON / executive PDF / technical PDF / BUKUKERJA XLSX / generic XLSX. |
| `/settings` | Paths to scan, retention, custom probe dir, root-mode hint, vuln-DB freshness, "Update tools" button, language toggle. |

### 7.2 Live scan view

`/scans/<id>` connects to `/api/scans/<id>/events` over **SSE**. Each `FindingDiscovered` event prepends a row in the "Live findings" panel via HTMX `hx-swap-oob`. Each `StageCompleted` event ticks the matching stage from `running` → `done`. **Skipped-due-to-privilege** stages render in muted grey ("Storage (skipped: root)") so users see the privilege gap explicitly.

### 7.3 Localisation

- All strings pass through `t()` Jinja filter.
- Two locale files in `pqcscan/i18n/`: `en.toml`, `ms.toml`. ~150 strings each.
- `pqcscan_lang=en|ms` cookie set by `POST /api/lang` from the Settings page.
- Framework view for BUKUKERJA always renders Malay (it's the source spec); other framework views and ad-hoc UI labels follow the user's choice.

### 7.4 Server config

- Bind: `127.0.0.1` only.
- Port: `8765` default; configurable in `/settings`.
- TLS: none in v1 (localhost-only — any future remote mode introduces TLS in its wrapper layer).

## 8. CLI surface

```
pqcscan daemon [--port 8765] [--db PATH] [--bind 127.0.0.1]
pqcscan scan   [--path PATH] [--server HOST] [--lang en|ms] [--watch] [--json] [--probes FAMILY,...] [--exclude-probes ...]
pqcscan status [--id N]
pqcscan scans  list

pqcscan baseline create --label LABEL [--scan ID]
pqcscan baseline list
pqcscan baseline diff --from BASELINE_LABEL --to SCAN_ID

pqcscan export --scan ID --format <cbom|pdf-exec|pdf-tech|xlsx-bukukerja|xlsx-generic> [--lang en|ms] -o FILE

pqcscan probes list [--family FAM] [--enabled|--disabled]
pqcscan probes enable PROBE_ID
pqcscan probes disable PROBE_ID
pqcscan probes test PROBE_ID

pqcscan update-tools [--pack PATH]
pqcscan health
pqcscan version
```

### 8.1 Defaults

- `pqcscan scan` with no flags runs every applicable probe across the whole host, using config-defined search roots (Section 8.3). Flags only narrow the default.
- If `pqcscan daemon` is running, `pqcscan scan` submits to it and streams via the daemon's bus. If not, it runs in-process, writes to the same SQLite, and exits. Same DB either way.

### 8.2 Shell exit codes

- `0` — scan completed, no findings worse than `low`.
- `1` — scan completed; `high` or `crit` findings present.
- `2` — scan failed (probe runner crashed / DB write error / etc.).
- `3` — invalid arguments.

### 8.3 Default search roots (`/etc/pqcscan/config.toml`)

```toml
[scan_roots]
filesystem  = ["/etc", "/opt", "/usr/local/etc", "/var/lib", "/var/www", "/srv", "/root/.ssh", "/home/*/.ssh", "/home/*/.gnupg"]
source_code = ["/srv/*", "/opt/*", "/var/www/*", "/home/*/projects/*"]
exclusions  = ["node_modules", ".git", "vendor", ".venv", "__pycache__", "target", "build"]

[network]
localhost_only = true
```

Equivalent paths shipped for Windows (`%PROGRAMDATA%`, `%USERPROFILE%`) and macOS.

## 9. Compliance engine + report renderers

### 9.1 Compliance engine

Each framework is a YAML rule file in `pqcscan/compliance/frameworks/` (and additionally any user files in `/etc/pqcscan/frameworks.d/`). Rules are simple matcher-verdict pairs:

```yaml
framework: cnsa2
title: Commercial National Security Algorithm Suite 2.0
rules:
  - match: { algorithm: RSA, key_size_lt: 3072 }
    clause: CNSA2:RSA-deprecated
    verdict: non-compliant
    deadline: 2030-12-31
    note: "RSA <3072 deprecated for NSS; transition by 2030."
  - match: { algorithm: ML-KEM-768 }
    clause: CNSA2:KEM-approved
    verdict: compliant
```

Engine pass: as each finding is committed to SQLite, the engine evaluates every rule across all configured frameworks and writes one row per match to `framework_views`. New frameworks → drop a YAML, no code changes.

Bundled framework YAMLs (eight):

1. BUKUKERJA MIGRASI PQC 2025 (Malaysian template)
2. NIST IR 8547 (PQC transition timeline)
3. NIST SP 800-227 (PQC migration guidance)
4. CNSA 2.0 (NSA Commercial National Security Algorithm Suite)
5. BSI TR-02102-1 (Germany)
6. ANSSI PQC roadmap (France)
7. MAS Notice 655 (Singapore)
8. ENISA PQC report (EU)

### 9.2 Renderers

| Renderer | Output | Audience |
|---|---|---|
| `cbom-cyclonedx` | `pqc-cbom-<scan>.json` (CycloneDX 1.6) | Tooling pipelines |
| `pdf-executive` | 4–6 page PDF — title, headline numbers, framework verdicts, top-10 findings, remediation summary | C-suite, auditors |
| `pdf-technical` | Full PDF — every finding with evidence, remediation, framework crosswalk | Engineers, sysadmins |
| `xlsx-bukukerja` | BUKUKERJA template — sheets `0_Inventory`, `1_SBOM`, `2_CBOM`, `3_RiskRegister`, `4_RiskAssessment`, `5_RiskMatrix`, `6_ProtocolCryptoMap`, `00_ReadMe` | MAMPU / regulator deliverable |
| `xlsx-generic` | Single-tab generic findings sheet | Other internal needs |

**Tech:**
- PDFs: **WeasyPrint** (HTML → PDF, BSD-3). HTML produced by Jinja templates; PDF rendered by WeasyPrint. No headless Chrome — works inside PyInstaller.
- XLSX: **openpyxl** (MIT).

All renderers respect `--lang en|ms`. BUKUKERJA xlsx remains Malay (source spec); the other four formats fully translate.

## 10. Build, packaging, offline pack

### 10.1 PyInstaller config

`--onefile`, build matrix on GitHub Actions across:

- `linux-amd64`, `linux-arm64` (Ubuntu 22.04 baseline; older glibc handled via auditwheel-style libc bundling)
- `windows-amd64` (MSVC runtime statically linked where possible)
- `darwin-amd64`, `darwin-arm64` (macOS 12+; codesign + notarise if Apple credentials are provided)

### 10.2 Artefacts

```
pqcscan-1.0.0-linux-amd64           ~340 MB
pqcscan-1.0.0-linux-arm64           ~340 MB
pqcscan-1.0.0-windows-amd64.exe     ~360 MB
pqcscan-1.0.0-darwin-amd64.tar.gz   ~340 MB
pqcscan-1.0.0-darwin-arm64.tar.gz   ~340 MB
pqc-update-pack-2026-04-29.tar.gz   ~200 MB   # vuln-DB + tool refresh
```

Each binary bundles: Python 3.11 runtime, all pip deps, Syft + Grype (per-arch), Semgrep OSS, tree-sitter grammars (Python/JS/Go/Java/PHP/Rust), liboqs, Grype-DB snapshot, OSV.dev offline mirror, Jinja templates, eight framework YAMLs, locale dicts.

### 10.3 Offline pack format

```
pack/
  manifest.json          # versions, checksums, build date
  syft-1.x.x-<arch>      # optional refresh
  grype-1.x.x-<arch>     # optional refresh
  grype-db.tar.gz        # latest vuln DB
  semgrep-rules/         # latest PQC rules
  osv-mirror/            # latest CVE deltas
  signatures/            # cosign sigs over each artefact
```

`pqcscan update-tools --pack <file>` verifies cosign signatures, atomically swaps cache, restarts daemon. **No network calls — ever — in offline mode.**

### 10.4 Service install

- **Linux:** `pqcscan-installer.sh` drops the binary in `/usr/local/bin/pqcscan` and installs a `systemd` unit (`pqcscan.service`, runs as system `pqcscan` user).
- **Windows:** MSI registers a Windows Service; UI shortcut in Start menu opens `http://127.0.0.1:8765`.
- **macOS:** `.pkg` installs to `/usr/local/bin` + a `launchd` plist.

### 10.5 First-run experience

Daemon starts → opens browser to `http://127.0.0.1:8765` → onboarding screen ("Run first scan?" / "Scan now") → live progress → results land in SQLite → dashboard rendered.

## 11. Module layout

```
pqcscan/
├── __main__.py              # CLI dispatcher (Click)
├── cli/                     # CLI subcommands
├── daemon/                  # FastAPI app, SSE handler, lifecycle
├── ui/                      # Jinja templates, static assets, HTMX endpoints, i18n
├── runner/                  # async probe runner, dependency graph, concurrency
├── probes/
│   ├── _base.py             # Probe ABC, Capability enum
│   ├── host/
│   ├── sbom/
│   ├── network/
│   ├── filesystem/
│   ├── code/
│   ├── vpn/
│   ├── storage/
│   ├── container/
│   ├── app/
│   ├── sign/
│   ├── dns_email/
│   ├── pqc_meta/
│   └── _user_loader.py      # /etc/pqcscan/probes.d/*.{py,yaml}
├── compliance/
│   └── frameworks/          # 8 bundled YAMLs
├── store/                   # SQLite schema, migrations, queries
├── cbom/                    # CycloneDX 1.6 builder, validator
├── renderers/               # cbom, pdf-exec, pdf-tech, xlsx-bukukerja, xlsx-generic
├── alg/                     # algorithm normaliser (OID/name/PQC mapping)
├── i18n/                    # en.toml, ms.toml, t() helper
├── update/                  # update-tools, offline pack verifier (cosign)
└── util/                    # logging (loguru), config loader, fs paths
```

## 12. Error handling, logging, testing

### 12.1 Error handling

- **Probe isolation.** Every probe runs inside `try/except`; a crash records a `probe_error` row (severity `info`, classification `error`) and the runner moves on. One bad probe never aborts the scan.
- **No silent fallbacks.** If `cve.grype` can't reach its DB, the probe records a `probe_error`, not a `no findings` result. The UI surfaces probe errors in `/probes` so users see real coverage, not implied coverage.
- **Atomic DB writes.** All scan-related SQLite writes happen in a single transaction per probe-finding batch; daemon crash mid-scan leaves a `running` scan that the next startup marks as `failed` with reason `daemon_restart`.

### 12.2 Logging

- `loguru` with JSON sink to `/var/log/pqcscan/daemon.log` (Linux paths shown).
- Per-scan correlation ID in every log line.
- Rotated daily, 14-day retention.
- No PII / no hostnames sent anywhere — logs stay local.

### 12.3 Testing

- **Unit:** pytest. Each probe has fixture-based tests feeding canned bytes/files and asserting findings shape. Target: 80% line coverage.
- **Integration:** Docker fixtures — Ubuntu 22.04 / RHEL 9 / Alpine 3.19 / Windows Server 2022 / macOS-13 (GitHub macOS runner). Each fixture has a known-bad crypto setup; CI asserts the scanner finds it.
- **Renderer golden files:** XLSX/PDF outputs diffed against committed golden files (skip volatile fields like timestamps).
- **CBOM round-trip:** every emitted CBOM validated against the CycloneDX 1.6 schema in CI.
- **License-compat test:** CI runs `pip-licenses` + a custom check that fails if any dep has a non-FOSS-compatible licence.

## 13. Future work (out of v1)

- **Database-at-rest TDE probes** — Postgres pgcrypto, MySQL keyring, MSSQL TDE, MongoDB encrypted storage. ~4 probes.
- **Message-queue / broker probes** — Kafka SASL_SSL, RabbitMQ, NATS, MQTT. ~4 probes.
- **Hardware-crypto probes** — TPM, PKCS#11 modules, smartcard readers. ~3 probes.
- **Remote-scan modes** — three wrappers around the v1 daemon's HTTP API:
  - **Agent → Hub (push):** agents POST results to a central hub over HTTPS+token. Behind-NAT-friendly.
  - **Hub → Agent (pull):** hub triggers each daemon's `POST /scan`. Best when central inventory + shell access already exists.
  - **Agentless network probe:** separate binary runs only the network-side probes against a remote hostname. Zero footprint on target. Misses host inventory + filesystem + source code.

## 14. Dependencies (FOSS-only)

| Package | License | Purpose |
|---|---|---|
| Python 3.11 | PSF (FOSS-compat) | Runtime |
| FastAPI | MIT | HTTP/SSE server |
| Jinja2 | BSD-3 | Templates |
| HTMX | BSD-2 | Frontend interactivity |
| Tailwind CSS (vendored) | MIT | Styling |
| openpyxl | MIT | XLSX output |
| WeasyPrint | BSD-3 | HTML → PDF |
| cyclonedx-python-lib | Apache-2.0 | CBOM build/validate |
| sqlalchemy + sqlite | MIT + Public-Domain | DB ORM |
| pydantic | MIT | Data shapes |
| click | BSD-3 | CLI parsing |
| loguru | MIT | Logging |
| cryptography | Apache-2.0 / BSD | X.509 + private-key parsing |
| paramiko | LGPL-2.1 | SSH probes |
| scapy | GPL-2 | Raw packet probes (root only) |
| pysnmp | BSD-2 | SNMP |
| impacket | Apache-modified | SMB / Kerberos |
| tree-sitter | MIT | AST source-code parsing |
| liboqs-python | MIT | PQC algorithm IDs |
| Syft (binary) | Apache-2.0 | SBOM |
| Grype (binary) | Apache-2.0 | CVE matching |
| Semgrep OSS | LGPL-2.1 | Code CBOM |
| cosign (binary) | Apache-2.0 | Update-pack signature verification |

CI gate fails if any added dep introduces a non-FOSS-compatible licence.

**Project licence — open question.** The repo currently ships under MIT (v1's `LICENSE`). v2 includes **scapy (GPL-2)** as a dependency for raw-packet probes; statically linking scapy into the PyInstaller artefact requires the combined work to be GPL-2-or-later. Three options to resolve before v2 ships:

1. **Relicense pqcscan v2 as GPL-2-or-later** — accepts scapy unmodified, broad FOSS posture.
2. **Replace scapy with a permissively-licensed alternative** (e.g., raw-socket usage in stdlib, or `dpkt` BSD-3) — keeps MIT, loses some packet-crafting helpers.
3. **Make scapy probes optional** — ship the core binary MIT-licensed without scapy; provide a separate `pqcscan-raw-packet-plugin` GPL-2 binary that users install separately.

This is a licensing decision for the user, not the implementation plan. Default recommendation: **option 2** — keeps MIT, minor functionality loss in the four scapy-touching probes (which can use stdlib `socket(AF_PACKET, SOCK_RAW)` directly).

---

## Appendix A — Full probe IDs (v1)

```
host.openssl.config         host.openssl.ciphers       host.openssl.engines
host.ssh.server_config      host.ssh.client_config     host.ssh.host_keys
host.kernel.keyring         host.kernel.crypto         host.pkcs11.modules
host.gnupg.config

sbom.os.dpkg                sbom.os.rpm                sbom.os.apk
sbom.os.pacman              sbom.os.brew               sbom.os.windows
sbom.lang.pip               sbom.lang.npm              sbom.lang.cargo
sbom.lang.gomod             sbom.lang.maven            sbom.lang.composer
sbom.syft                   cve.grype                  cve.osv_offline

net.ports.tcp               net.ports.udp
net.tls.https               net.tls.imaps              net.tls.pop3s
net.tls.smtps               net.tls.ldaps              net.tls.mqtts
net.ssh.handshake
net.starttls.smtp           net.starttls.imap          net.starttls.pop3
net.starttls.ldap           net.starttls.ftp
net.ike.v1v2
net.rdp.negotiation         net.smb.dialect            net.smb.encryption
net.db.mysql_tls            net.db.postgres_tls        net.db.mssql_tls
net.db.mongo_tls            net.db.redis_tls
net.snmp.version            net.kerberos.asreq

fs.cert.x509                fs.cert.privkey
fs.conf.nginx               fs.conf.apache             fs.conf.sshd
fs.conf.openssl_cnf         fs.conf.vsftpd             fs.conf.dovecot
fs.conf.postfix             fs.conf.bind9              fs.conf.haproxy
fs.conf.envoy

code.semgrep.pqc            code.ts.python             code.ts.javascript
code.ts.go                  code.ts.java               code.ts.php
code.ts.rust

vpn.wireguard               vpn.openvpn.config         vpn.tailscale.state

storage.luks.headers        storage.bitlocker          storage.zfs.encryption
storage.dmcrypt             storage.fscrypt

container.runtime.detect    container.image.sbom
k8s.ingress.tls             k8s.secrets.types          k8s.helm.releases
k8s.mesh.mtls

app.jwt.env_alg             app.oauth.jwks             app.dotenv.secrets
app.spring.properties       app.nginx.jwt_validation

sign.gpg.keyrings           sign.repo.aptdnf_keys      sign.code.authenticode
sign.git.signing_keys       sign.image.cosign

dns.dnssec.zones            email.dkim.selectors       email.smime.certs
web.webauthn.config         trust.system_roots

pqc.hybrid.detector         pqc.alg.normaliser

aux.clock.cert_validity     aux.distrust.root_list
```

## Appendix B — Algorithm classification (PQC threat model)

| Class | Algorithms | Reason |
|---|---|---|
| Sangat Tinggi (very high) | RSA <3072, ECDSA <P-384, DSA, DH <3072, MD5, SHA-1, RC4, DES/3DES, SNMPv1/v2c | Broken classically or broken by Shor / Grover |
| Tinggi (high) | RSA-3072, EC P-384, Ed25519, IKE DH-14/15/16, AES-128 CBC | Vulnerable to Shor on a CRQC (~4096 logical qubits) |
| Sederhana (medium) | AES-128 GCM, SHA-256, Kerberos AES-128 | Grover halves effective key strength |
| Rendah (low) | AES-256, SHA-512, Kerberos AES-256 | Safe with doubled key sizes per NIST SP 800-227 |
| PQC Ready | ML-KEM, ML-DSA, SLH-DSA, hybrids (X25519MLKEM768, P256+ML-KEM-768) | NIST FIPS 203/204/205 standardised + IETF hybrid drafts |
