# pqcscan v2 — Project Status & Resume Guide

| | |
|---|---|
| **Date** | 2026-07-21 |
| **Branch / commit** | `main` |
| **Version** | `0.9.11` |
| **Probes** | 177 registered across 15 families |
| **Frameworks** | 19 compliance YAMLs |
| **Tests** | 1226 passed / 1 skipped locally (Python 3.11) |
| **Status** | Design-doc target shipped, plus four loops (§7 coverage+UX, §8 deferred-items + bilingual + any-OS, §9 the 0.8.x–0.9.4 precision/decision loop, §10 the 0.9.5–0.9.11 coverage-completeness + FOSS-verification loop). See `CHANGELOG.md` for the authoritative per-version record — it is kept current every release; this file is a coarser resume guide. |

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

177 probes registered; SQLite store; web UI at all 9 spec'd pages with EN/MS toggle; PDF/XLSX/CBOM exports; 19 compliance frameworks all evaluated against findings; cross-OS PyInstaller binary build pipeline; offline-pack framework with broad-ecosystem CVE matching.

## 2. What's shipped

### Foundations (Plan A)

| Layer | Path | Notes |
|---|---|---|
| Core types & PQC classifier | `src/pqcscan/core/{types,alg}.py` | Capability/ProbeFamily/Classification/Severity enums; Finding/Component dataclasses; classify() per spec Appendix B |
| SQLite store | `src/pqcscan/store/{schema,migrations,repo}.py` | scans, components, findings, graph_edges, framework_views, baselines; `check_same_thread=False`; baseline create + diff helpers |
| Async runner + event bus | `src/pqcscan/runner/*.py` | Probe isolation, per-probe timeout, asyncio.gather per family, Finding/ScanCompleted SSE events |
| Probe ABC + registry | `src/pqcscan/probes/{_base,_registry}.py` | `default_registry()` seeds 177 probes |
| FastAPI daemon + API | `src/pqcscan/daemon/app.py` | health, version, scans, findings, events SSE, baselines, scan diff |
| Web UI | `src/pqcscan/ui/{routes,templates,static,i18n}.py` | 9 pages; EN/MS toggle via `pqcscan_locale` cookie; vanilla forms, no JS deps |
| CycloneDX 1.7 CBOM + PDF/XLSX renderers | `src/pqcscan/{cbom,renderers}/*` | CBOM JSON, PDF (technical/executive), XLSX (BUKUKERJA template + generic) |
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

**Detection coverage is done** (five research passes; see §10 and
`docs/COMPETITIVE-LANDSCAPE.md`). The roadmap is now maturity / validation /
currency, **not** more probes. Full ranked list in
[`docs/TODO.md` → Roadmap](TODO.md#roadmap--post-v0911-2026-07-21); in short:

1. **Cut a 1.0** — the tool is feature-complete + released; add a stability
   contract (probe IDs, CBOM schema, SARIF, exit codes) and tag `v1.0.0`.
2. **Standards-tracking (standing discipline)** — NIST IR 8547 will finalize
   (dates may shift); HQC + FIPS 206/FN-DSA will get OIDs → update `core/alg.py`
   + the deadline logic when they land.
3. **Publish a discovery precision/recall corpus** — the field's first (no FOSS
   crypto-*discovery* benchmark exists); we already have the harness + 51-OID
   oracle.
4. *(demand-driven)* live QUIC sniffing · binary crypto-constant expansion ·
   pkilint-level cert profile validation.
5. *(design decision)* migration assistance is a deliberate non-goal today
   (we inventory, not orchestrate); continuous-monitoring/trend view builds on
   the existing baselines + diff.

## 6. Pointers

- **Design spec** — [`docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md`](superpowers/specs/2026-04-29-pqcscan-v2-design.md)
- **MVP plan** — [`docs/superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md`](superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md)
- **Malaysia PQC source references** — [`docs/references/malaysia-pqc.md`](references/malaysia-pqc.md)
- **GitHub repo** — https://github.com/orengacademy/pqc-scanner2 (private)
- **README** — [`README.md`](../README.md)

## 7. 2026-07-20 coverage + UX loop (v0.7.0 → v0.7.5)

A focused loop to widen coverage ("scan everything applicable"), lift the web
UI to production quality, and make findings actionable. Shipped as PRs #41–#46,
each with its own tests, all green through CI.

**Shipped**

- **v0.7.0 — classifier + remediation foundation.** `core/alg.py` OID table
  extended to the full FIPS 203/204/205 arc + RSASSA-PSS/Ed448/DSA/curve
  handling; RSA signature names no longer fall through to INFO; HNDL /
  CNSA-2.0 deadline logic (`hndl_exposed`, `migration_deadline`). New
  `core/remediation.py` centrally enriches every finding with a typed PQC
  replacement (target, FIPS standard, deadline, HNDL flag). New
  `core/keyhealth.py` ROCA (CVE-2017-15361) + small-modulus detection.
- **v0.7.1 — target/domain scanning.** The runner threads
  `scan_paths`/`server_target`/`ot_targets` into the `ScanContext`, so the
  ~30 network probes and the OT family (previously dormant — nothing ever set
  a target) now fire. `pqcscan scan --target/--path/--ot`; `POST /api/scans`
  body; a dashboard "Run a scan" form.
- **v0.7.2 — coverage wave (147 → 154 probes).** `fs.conf.{haproxy,envoy,
  traefik,caddy}` reverse-proxy/mesh TLS config; `host.rng.config`,
  `host.pam.hashing`, `host.ssh.moduli` long-tail host posture.
- **v0.7.3 — reporting.** SARIF 2.1.0 renderer (GitHub Code Scanning) + QRAMM
  compliance framework (→ 11 frameworks).
- **v0.7.4 — web UI.** Self-contained fonts (no network fetch — air-gap
  correct), light/dark theme with a persisted toggle, dynamic version.
- **v0.7.5 — findings UX.** Inline PQC-migration chips (target + deadline +
  HNDL badge) on every finding, a text filter, and live SSE progress.

**Deferred — with rationale** (kept honest; these are the XL / heavy-dep /
flaky-live-network items intentionally not attempted this loop):

- **TLS 1.3 served-chain `signatureAlgorithm`** — needs a full TLS 1.3 key
  schedule to decrypt the Certificate message. Real work, no reliable way to
  unit-test without a live 1.3 server; deferred over shipping flaky code.
- **Live Kerberos etype / IKE SA transform enumeration** — active-network
  probes that can't be exercised deterministically in CI. `net.kerberos.asreq`
  and `net.ike.v1v2` already cover the passive/handshake angle.
- **PCAP ingestion** — would add a heavy `scapy`/`pyshark` dependency to a
  binary whose whole premise is being small and self-contained; poor fit.
- **Tree-sitter AST rebuild of `code.ts.*`** — XL grammar-bundling effort; the
  regex probes stay in place until it's worth the binary-size cost.
- **SBOM → crypto-primitive mapping** — needs a curated library→primitive
  corpus to be worth shipping; a data-collection task more than a code one.

## 8. 2026-07-20 continuation — deferred items + bilingual + any-OS (v0.8.0)

A second loop that closed **every** item §7 deferred, made reports + web fully
bilingual, and made the scanner applicable on any OS. Shipped as PRs #48–#52
(163 probes; 826 tests).

- **Fully bilingual web (EN + Bahasa Melayu).** Every remaining hardcoded string
  in the dashboard, scan-detail, and scans pages is now translated (82 new i18n
  keys/locale); the whole UI flips with the `pqcscan_locale` cookie.
- **Reports rebuilt — 10/10 + bilingual.** Technical + executive reports share a
  context builder and render a readiness gauge, band cards, a **priority-
  remediation table grouped by NIST replacement (HNDL-first)**, an HNDL callout,
  the surface breakdown, the compliance matrix, and the NACSA timeline — in EN
  **or** MS via a `lang` param (CLI `--lang`, API `?lang=`, web routes follow
  the locale cookie). The HTML report needs no WeasyPrint, so it's the universal
  path in the frozen binary.
- **Deferred backend items — all shipped, none skipped:**
  - `net.tls.cert_chain_tls13` — real TLS 1.3 handshake + RFC 8446 key schedule
    (verified against RFC 8448 vectors) + AEAD-decrypt of the encrypted
    Certificate. The "TLS 1.3 served-chain" gap is closed.
  - `net.kerberos.etypes` (ASN.1 AS-REQ) and `net.ike.transforms` (IKE_SA_INIT)
    — the live etype / IKE-transform enumeration.
  - `fs.pcap.crypto` — **PCAP/pcapng ingestion with a pure-Python parser** (no
    scapy — the self-contained premise is preserved).
  - `sbom.crypto_map` — the SBOM → crypto-primitive mapping (44-library corpus).
  - `code.crypto_primitives` — broadened cross-language code detection (31
    patterns, 13 languages) instead of native tree-sitter (which would break the
    any-OS self-contained binary).
- **Any-OS applicability.** `host.windows.schannel` + `host.macos.keychain`
  native probes, a cross-OS `host.platform_info`, a graceful-degradation test
  (every `applies()` safe on any OS; every module imports with no top-level
  OS-specific imports), and a documented platform-compatibility floor
  (`docs/DEPLOYMENT.md`): Linux glibc 2.17+ (RHEL/OL 7.9+), macOS 11+/10.15+,
  Windows 8+.

**Still deferred (with rationale):** native tree-sitter grammars (platform-
specific compiled artifacts would break the any-OS self-contained binary — the
regex/keyword probes cover the ground instead); the `macos-13` (x86_64) release-
matrix line is prepared but needs a `workflow`-scoped token to push.

## 9. 2026-07-21 continuation — 0.8.x hardening → 0.9.x precision + decision loop

Shipped as PRs #53–#69 (see `CHANGELOG.md` 0.8.1–0.9.4 for full detail). Highlights:

- **0.8.x** — DB-column + F5/NetScaler appliance scanning, source-code AST
  precision, live passive TLS sensing (`net.sniff.live`) with TCP stream
  reassembly, an accuracy benchmark harness with a CI precision/recall gate.
- **0.9.0** — coverage + interop + agility expansion (172 probes, 19 frameworks).
- **0.9.1** — reachability/executability confirmation: ELF `.dynsym`
  intersection proves linked crypto is actually *invoked*; linked-only hits are
  down-ranked to low confidence.
- **0.9.2** — Zeek/Suricata IDS-log ingestion (`fs.zeek.logs`, 174th probe),
  migration-readiness score, multi-axis exposure register.
- **0.9.3** — per-language remediation snippets (before→after fixes, projected
  into SARIF), `--fail-on` CI/CD gate, reusable GitHub composite Action,
  `docs/CICD.md`.
- **0.9.4** — `fs.binary.crypto` runs on a plain scan (default system
  executable roots + magic-bytes pre-read guard); skipped-privilege notes carry
  explicit high confidence.

## 10. 2026-07-21 loop — coverage-completeness + FOSS verification (0.9.5 → 0.9.11)

An autonomous engineering loop that closed the remaining coverage candidates
surfaced by **three deep-research passes** (a commercial-vendor pass, two FOSS
passes incl. a registry-anchored completeness sweep against **Santander
PQCTools** CADI/PQCI). Shipped as PRs #70–#79. The recurring goal — "cover
EVERYTHING, precise, accurate, reliable" — is met with **no open frontier**.

- **0.9.5** (#71) — `net.telnet.plaintext` + `net.tftp.service` (cleartext-
  protocol probes) + **on-ramp signature recognition** (MAYO/SNOVA/CROSS/UOV/
  HAWK/SQIsign added to `core.alg`, were classified INFO).
- **0.9.6** (#72) — **binary crypto-constant signatures** (`_crypto_constants.py`):
  16 sigs (AES S-boxes, SHA/MD/Keccak round constants, ChaCha sigma, Blowfish
  P-array) detect static/stripped binaries that `.dynsym` linkage misses. Gated
  on "no library detected". (Also fixed a real regression from 0.9.4: bounded the
  default sweep with a file budget + `await asyncio.sleep(0)` so the runner's
  30 s per-probe timeout can preempt; scoped the e2e integration scans to `--path`.)
- **0.9.7** (#73) — **passive PQC key_share grading** (`net.sniff.live` now scores
  a key_share offer above a bare supported_groups advertisement); **FIPS 204/205
  pre-hash OIDs** (HashML-DSA/HashSLH-DSA, CSOR .32–.46, NIST-CSOR-verified); a
  **51-OID ground-truth recall oracle** (measured PQC-discovery accuracy — no FOSS
  benchmark exists); fixed the unsatisfiable `[active]` liboqs pin.
- **0.9.8** (#74) — `host.openssl.pqc_provenance`: synthesizes `openssl version` +
  `list -providers` into a **native / oqs-provider / none** verdict (UMBC-survey
  requirement).
- **0.9.9** (#75) — centralized `fs.cert.pqc_x509` recognition on `core.alg`
  (was a stale local table) → now recognizes **pre-hash + composite + Falcon**
  certs; added the probe's first test suite. Audit confirmed no other probe
  carries a drifting OID table.
- **0.9.10** (#78) — `fs.binary.crypto` recognizes **s2n-tls** (soname) + **AWS-LC**
  (banner-disambiguated). Docs: completeness-sweep verdict — pqcscan covers every
  FOSS discovery modality **and five categories the entire FOSS field leaves
  empty** (IKE/VPN, TPM/HSM/PKCS#11, K8s/mesh, DKIM/email, Semgrep-PQC).
- **0.9.11** (#79) — **QUIC PQC probing** (`_quic.py`): decrypts the QUIC Initial
  packet (client keys via HKDF from the DCID, v1/RFC 9001 + v2/RFC 9369, verified
  against the RFC 9001 A.1 vector; AES-128-ECB header protection + AES-128-GCM),
  reassembles the CRYPTO-frame ClientHello, and inventories its offered PQC groups
  via `fs.pcap.crypto`. **The one surface no other FOSS — or verified commercial —
  tool covers.** Pure `cryptography` + stdlib.
- Housekeeping: #76 (candidate close-out docs), #77 (probe count corrected to 177).

**Deferred (documented rationale, not gaps):** JA4/JA4X emission (a client-
correlation fingerprint with no PQC signal — JA4 records only the extension
*type*); publishing a labeled discovery precision/recall corpus (a data/release
task; the 51-OID oracle + benchmark harness are the start). See `docs/TODO.md`
and `docs/COMPETITIVE-LANDSCAPE.md` (2026-07-21 completeness sweep) for the full
FOSS/commercial cross-check.

**CI note:** releases in this loop were admin-merged on local-green + ruff-clean
(the full suite is the gate; the ~60-min GitHub CI — dominated by the
`net.ct.crtsh` external call + PDF-render + subprocess-scan tests — validates
asynchronously on push). The full suite runs in ~2.5 min locally
(`PYTHONPATH=src .venv/bin/python -m pytest -q`).

---

_Last updated: 2026-07-21. Update this file at the end of any session that ships meaningful work._
