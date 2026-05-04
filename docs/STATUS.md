# pqcscan v2 — Project Status & Resume Guide

| | |
|---|---|
| **Date** | 2026-05-04 |
| **Branch / commit** | `main @ 656d7af` |
| **Version** | `0.1.0` |
| **Tests** | 139 passed, 0 failed (Python 3.11) |
| **Probes** | 51 / 102 registered (50 %) |
| **Status** | Paused mid-Plan-B (batch 9 of ~17) |

## 1. TL;DR

Plan A (MVP foundation) shipped end-to-end on 2026-04-29. Plan B (probe expansion) ran through batches 1–9 over the following session and now sits at **51 / 102 probes** with **all foundations stable** (asyncio runner, FastAPI daemon + SSE, click CLI, Jinja+HTMX web UI, CycloneDX 1.6 CBOM exporter, SQLite store, in-memory event bus, probe registry, capability detection, hybrid-privilege model). The session paused due to a Claude usage limit, not because of any blocker. Resuming is mechanical — the probe-production pattern is established and follow-up batches are copy-pattern + test work.

## 2. What's shipped

### Foundations (Plan A)

| Layer | Path | Notes |
|---|---|---|
| Core types & PQC classifier | `src/pqcscan/core/{types,alg}.py` | Capability, ProbeFamily, Classification, Severity enums; Finding/Component dataclasses; OID/friendly-name normalisation; classify() routes to Sangat-Tinggi/Tinggi/Sederhana/Rendah/PQC-Ready per spec Appendix B |
| SQLite store | `src/pqcscan/store/{schema,migrations,repo}.py` | 6 tables: scans, components, findings, graph_edges, framework_views, baselines; `check_same_thread=False` for cross-thread daemon use |
| Async runner + event bus | `src/pqcscan/runner/{event_bus,capabilities,runner}.py` | Probe isolation, per-probe timeout (30 s default), privilege-skip records, asyncio.gather per family, Stage/Finding/ScanCompleted events |
| Probe ABC + registry | `src/pqcscan/probes/{_base,_registry}.py` | id/family/requires/framework_tags metadata; `default_registry()` seeds the built-in probes |
| FastAPI daemon + SSE | `src/pqcscan/daemon/{app,sse}.py` | `/api/{health,version,scans,scans/<id>/{findings,events}}`; threading.Thread + asyncio.run for background scans |
| Click CLI | `src/pqcscan/cli/{main,scan,daemon_cmd,export}.py` | `version, scan, scans, status, daemon, export` subcommands; exit codes 0/1/2/3 |
| Web UI | `src/pqcscan/ui/{routes,templates/*,static/{htmx,tailwind}}` | Dashboard, scans list, live SSE-streamed scan detail |
| CycloneDX 1.6 CBOM | `src/pqcscan/cbom/builder.py` | crypto-asset components + nistQuantumSecurityLevel mapping + UUID serial number |
| Util | `src/pqcscan/util/paths.py` | OS-aware default DB locations + `PQCSCAN_DB_PATH` env override |

### Probes (Plan B batches 1–9)

| Family | Count | Probe IDs |
|---|---:|---|
| Host crypto | 6 | `host.openssl.config`, `host.openssl.ciphers`, `host.openssl.engines`, `host.ssh.server_config`, `host.ssh.client_config`, `host.gnupg.config` |
| Filesystem | 6 | `fs.cert.x509`, `fs.cert.privkey`, `fs.conf.nginx`, `fs.conf.apache`, `fs.conf.sshd`, `fs.conf.openssl_cnf` |
| Source code | 1 | `code.ts.python` (regex placeholder for tree-sitter) |
| SBOM | 6 | `sbom.os.dpkg`, `sbom.os.rpm`, `sbom.os.apk`, `sbom.lang.pip`, `sbom.lang.npm`, `sbom.lang.gomod` |
| Network TLS direct | 6 | `net.tls.https`, `net.tls.imaps`, `net.tls.pop3s`, `net.tls.smtps`, `net.tls.ldaps`, `net.tls.mqtts` |
| STARTTLS | 5 | `net.starttls.smtp`, `net.starttls.imap`, `net.starttls.pop3`, `net.starttls.ftp`, `net.starttls.ldap` (last is a stub) |
| Port discovery + DB | 5 | `net.ports.tcp`, `net.db.postgres_tls`, `net.db.mongo_tls`, `net.db.redis_tls`, `net.db.mysql_tls` (last is a stub) |
| VPN beyond IKE | 3 | `vpn.wireguard`, `vpn.openvpn.config`, `vpn.tailscale.state` |
| Storage at rest | 5 | `storage.luks.headers`, `storage.bitlocker`, `storage.zfs.encryption`, `storage.dmcrypt`, `storage.fscrypt` |
| Container & K8s | 6 | `container.runtime.detect`, `container.image.sbom`, `k8s.ingress.tls`, `k8s.secrets.types`, `k8s.helm.releases`, `k8s.mesh.mtls` |
| Aux & PQC meta | 3 | `aux.clock.cert_validity`, `pqc.alg.normaliser` (meta, disabled by default), `pqc.hybrid.detector` (placeholder) |

> Each probe declares `framework_tags` already including `bukukerja:*` and `mykripto:*` so the Plan C compliance engine can map findings to BUKUKERJA / MyKripto Migration Framework / NACSA Arahan KE No. 9 without code changes.

### Documentation & references

- Design spec — `docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md`
- MVP plan — `docs/superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md`
- Malaysia PQC sources — `docs/references/malaysia-pqc.md`
- Brainstorm visual mockups — `.superpowers/brainstorm/` (gitignored)

## 3. What's deferred

### 3.1 Per-spec §13 (explicitly v2.next, ~11 probes)

These were excluded from the MVP plan and remain explicitly out of scope:

- **Database at-rest TDE** — `db.pg.pgcrypto`, `db.mysql.keyring`, `db.mssql.tde`, `db.mongo.encrypted_storage` (4 probes).
- **Message queues & brokers** — `mq.kafka.tls`, `mq.rabbitmq.tls`, `mq.nats.tls`, `mq.mqtt.broker` (4 probes).
- **Hardware crypto** — `hw.tpm.algorithms`, `hw.pkcs11.modules`, `hw.smartcard.readers` (3 probes).

### 3.2 Batched but not yet implemented (~50 probes, the bulk of the remaining work)

| Future batch | Probes | Sizing |
|---|---|---|
| **B10 — App-config crypto** | `app.jwt.env_alg`, `app.oauth.jwks`, `app.dotenv.secrets`, `app.spring.properties`, `app.nginx.jwt_validation` | 5 — fast, file-scan style |
| **B11 — Signing & integrity** | `sign.gpg.keyrings`, `sign.repo.aptdnf_keys`, `sign.code.authenticode`, `sign.git.signing_keys`, `sign.image.cosign` | 5 — fast |
| **B12 — DNS / email / web auth** | `dns.dnssec.zones`, `email.dkim.selectors`, `email.smime.certs`, `web.webauthn.config`, `trust.system_roots` | 5 — fast |
| **B13 — Lang SBOM expansion** | `sbom.os.pacman`, `sbom.os.brew`, `sbom.os.windows`, `sbom.lang.cargo`, `sbom.lang.maven`, `sbom.lang.composer` | 6 — fast, copy-pattern |
| **B14 — Tree-sitter source code** | `code.ts.javascript`, `code.ts.go`, `code.ts.java`, `code.ts.php`, `code.ts.rust` | 5 — needs tree-sitter grammars; medium complexity |
| **B15 — Hybrid PQC + alg metadata** | Replace `pqc.alg.normaliser` and `pqc.hybrid.detector` placeholders with real probes that emit findings | 2 — fast |
| **B16 — Binary protocols (slow)** | `net.ssh.handshake`, `net.ike.v1v2`, `net.rdp.negotiation`, `net.smb.dialect`, `net.smb.encryption`, `net.snmp.version`, `net.kerberos.asreq` | 7 — each protocol needs its own packet encoder; ~3× wall-time of a config-scan probe |
| **B17 — Aggregator: SBOM-driven CVE** | `cve.grype` (subprocess Grype), `cve.osv_offline` (OSV.dev mirror) | 2 — needs offline DB snapshot |

### 3.3 Implementation stubs (probes that exist but emit a deferral-INFO)

- `net.starttls.ldap` — needs an ASN.1 DER encoder for the LDAP `1.3.6.1.4.1.1466.20037` ExtendedRequest. Workaround: use `net.tls.ldaps` on port 636.
- `net.db.mysql_tls` — needs a MySQL CLIENT_SSL handshake encoder.

## 4. How to resume

```bash
# 1. Clone (or fetch) the repo.
git clone https://github.com/orengacademy/pqc-scanner2 pqc-scanner2
cd pqc-scanner2

# 2. Install Python 3.11 + dev deps. On the original session host:
sudo apt-get install -y python3.11 python3.11-venv
python3.11 -m ensurepip --upgrade
python3.11 -m pip install --break-system-packages \
    fastapi 'uvicorn[standard]' sqlalchemy jinja2 click pydantic loguru \
    'cryptography>=42' cyclonedx-python-lib httpx pytest pytest-asyncio \
    pytest-cov ruff mypy

# 3. Verify everything still passes (~100 s on shared FS, ~30 s on native FS).
PYTHONPATH=src python3.11 -m pytest -q

# 4. Smoke-run the daemon + UI.
PYTHONPATH=src python3.11 -m pqcscan daemon &
xdg-open http://127.0.0.1:8765   # or curl http://127.0.0.1:8765/api/health

# 5. Run a one-shot scan on the host.
PYTHONPATH=src python3.11 -m pqcscan scan --json

# 6. Export CycloneDX 1.6 CBOM.
PYTHONPATH=src python3.11 -m pqcscan export --scan 1 --format cbom -o cbom.json
```

> **Filesystem note.** The original session ran on a `/mnt/hgfs/...` VMware shared mount, which slows pip and pytest substantially. If resuming on the same host, consider cloning into `~/pqc-scanner2` (native ext4) for ~5× speedup.

> **Git note.** The original sessions used `git -c safe.directory='*' …` due to dubious-ownership detection on the shared mount. Either keep that flag or set per-repo: `git config safe.directory '/path/to/pqc-scanner2'`.

## 5. Recommended next-steps roadmap (priority order)

The 50 % probe milestone is a natural pivot point. **Don't keep grinding probes** — instead ship the parts of the v1 design that turn the 51 probes already shipped into something users can actually consume.

| Order | Item | Why now | Effort |
|---:|---|---|---|
| **1** | **Plan C — Compliance engine + 8 framework YAMLs** | All 51 probes already carry `framework_tags`. A small YAML evaluator + 8 rule files unlocks the per-framework dashboard that turns scans into auditor-ready evidence. Direct value-add for Malaysia BUKUKERJA / MyKripto / NACSA users. | 2 batches (~1 session) |
| **2** | **Plan D — PDF + BUKUKERJA XLSX renderer** | Same SQLite read path as the existing CycloneDX builder; Jinja → WeasyPrint for PDF; openpyxl over the BUKUKERJA template for XLSX. Gives stakeholders something to *hand to* an auditor. | 2 batches (~1 session) |
| 3 | Plan B batches 10–15 — fast follow-up probes (app-config, signing, DNS/email, lang SBOM, tree-sitter, hybrid PQC) | Adds ~31 probes via copy-pattern work. | ~3 batches |
| 4 | Plan E — Full UI (Settings page, Frameworks page, Probes admin, Baselines + diff, EN/MS i18n toggle) | Closes the UX gaps in the MVP UI. | ~1 session |
| 5 | Plan B batch 16 — binary-protocol probes | Slowest, ~3× the wall-time of config-scan probes. | ~2 sessions |
| 6 | Plan F — PyInstaller cross-OS packaging + offline pack | Distribution-ready binaries. Significant CI work. | ~1 session |
| 7 | Plan B batch 17 — `cve.grype` + `cve.osv_offline` | Vulnerability layer over the SBOM probes. | ~1 batch |
| 8 | v2.next — DB-TDE / message-queue / hardware-crypto probes (per-spec §13 deferral) | Specialised; lowest-impact-per-effort. | optional |

**Highest-value next session:** start Plan C (compliance engine) — small, well-bounded, immediately unlocks differentiated value for the Malaysia audience already encoded in `framework_tags`.

## 6. Key decision log

Quick reference; all of these are recorded in the design spec or commit messages.

| Decision | Choice | Rationale |
|---|---|---|
| OS targets | Linux + Windows + macOS | "Run on any server" requirement |
| Distribution | Python 3.11 + PyInstaller per OS | User-selected over Go in the brainstorm |
| Privilege model | Hybrid — run as user, flag root-only as `skipped_privilege` | Lowest install friction, explicit coverage gaps |
| Web UI access | Localhost-only, no login | OS-level access is the trust boundary |
| Frontend | Jinja + HTMX + SSE, vendored Tailwind | Python-native, no Node toolchain |
| DB engine | SQLite (`/var/lib/pqcscan/pqcscan.db` Linux), `check_same_thread=False` | Local single-host deploy; threaded daemon access |
| Retention | 30 days + all baselines forever | Bounded growth; baselines are durable |
| Offline | Bundle Syft + Grype + Grype-DB snapshot + Semgrep + tree-sitter | Airgap-compatible day-1 |
| Compliance frameworks | All 8 (BUKUKERJA + NIST IR 8547 + NIST SP 800-227 + CNSA 2.0 + BSI TR-02102-1 + ANSSI PQC + MAS Notice 655 + ENISA PQC) | YAML-driven; no code changes per framework |
| Future remote-scan | Daemon HTTP+JSON API on `127.0.0.1` is the contract; v1 ships zero remote code | YAGNI for v1, no demolition later |
| RSA classification boundary | RSA <3072 → Sangat Tinggi, RSA ≥3072 → Tinggi (per spec Appendix B) | Caught in test refactor — plan's RSA-2048 → Tinggi assumption was wrong |
| Project licence | Currently MIT; **scapy GPL-2 dependency = open question** | Three options noted in spec §14: keep MIT (drop scapy), GPL-2 the project, or split scapy probes into a separate plugin |

## 7. Pointers

- **Design spec** — [`docs/superpowers/specs/2026-04-29-pqcscan-v2-design.md`](superpowers/specs/2026-04-29-pqcscan-v2-design.md)
- **MVP plan** — [`docs/superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md`](superpowers/plans/2026-04-29-pqcscan-v2-mvp-implementation.md)
- **Malaysia PQC source references** — [`docs/references/malaysia-pqc.md`](references/malaysia-pqc.md)
- **GitHub repo** — https://github.com/orengacademy/pqc-scanner2 (private)
- **README** — [`README.md`](../README.md)

---

_Last updated: 2026-05-04. Update this file at the end of any session that ships meaningful work._
