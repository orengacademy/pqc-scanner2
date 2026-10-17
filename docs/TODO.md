# pqcscan — backlog

Gaps surfaced by the 2026-05-05 coverage audit against 12 peer projects
(LiuYuancheng/Network_PQC_Attack_Resistance_Evaluator, cyberjez/PQC-Scanner,
csnp/cryptoscan, Hacker21-punk/pqscan, anvilsecure/pqcscan, pqcworld.com,
checkpqc.app, wiz.io/pqc-tester, pqscan.io, et al.).

We already cover the majority of what they do; the items below are the
gaps worth filling, ranked by leverage.

## Fleet mode — shipped in v0.10.0–v0.10.2 (2026-10-17)

Design: `docs/superpowers/specs/2026-10-16-pqcscan-fleet-agent-design.md`;
operator guide: `docs/FLEET.md`.

- [x] Bundle format, enroll/ingest API, hosts table, fleet exports, `agents`/`fleet` CLI (v0.10.0)
- [x] `pqcscan agent` loop, `/fleet` pages (EN/MS), deployment recipes (v0.10.1)
- [x] Host-agnostic parity key + `fleet.drift` on ingest, labels → Mosca inputs,
      crypto-agility score, per-host retention (v0.10.2)

### Open items (deferred by ruling)
- [ ] **Split-on-413 resend** (spec §5): bundles over the raw cap fail at dump time; split
      into several bundles instead.
- [ ] **Label removal on re-enroll**: `upsert_host` merges labels, so a label can never be
      removed without `agents revoke`/re-enroll.
- [ ] **Plain-HTTP warning on a non-loopback daemon bind** (spec §3.3).
- [ ] **Render fleet exports from scan-id lists** instead of copying rows into a temporary
      rollup (the copy is batched but still O(hosts × findings) per export).
- [ ] **Run `packaging/fleet/windows-task.ps1` on a Windows host**: reviewed by reading only;
      the owner check depends on the default-owner policy for elevated admins.
- [ ] **Postgres collector**: wired (`pip install 'pqcscan[fleet-pg]'`, `postgresql+psycopg://`)
      but untested; add a CI job against a service container.
- [ ] **Parity key refinements**: `word:digits` tokens are normalised lossily, URL and
      IPv6-zone forms are not; values containing `=` cannot be used in the `/fleet` label filter.
- [ ] **`criticality` host label → exposure weighting** (spec §3.1): only the Mosca labels are wired.
- [ ] **Per-host crypto-agility on `/fleet`**: the score exists per scan in reports; `fleet_summary`
      returns grouped counts only, so a per-host score needs a cheap aggregate (store it on the scan row).
- [ ] **Collector load test** (spec §4): 500 concurrent bundles, p95 ingest < 2 s; manual follow-up.
- [ ] **Stable machine id in containers**: persist a generated id in the state dir when no
      `/etc/machine-id` exists.

## Roadmap — post-v0.9.11 (2026-07-21)

**Detection coverage is done.** Five deep-research passes (see
`docs/COMPETITIVE-LANDSCAPE.md`) confirm pqcscan covers every FOSS discovery
modality, five categories the FOSS field leaves empty, and QUIC that no other
FOSS/verified-commercial tool reads. So the next frontiers are **maturity,
external validation, and staying current — not more probes.** Adding niche
probes now is busywork; build detection only when a real user need pulls it.

### Tier 1 — highest leverage
- [ ] **Cut a 1.0.** The tool is feature-complete, comprehensively verified, and
      shipping cross-platform binaries. A `1.0` with an explicit **stability
      contract** — probe IDs, the CycloneDX CBOM schema, SARIF output, and CLI
      exit codes — signals maturity and lets CI/downstream depend on it.
- [ ] **Standards-tracking (standing discipline).** The landscape still moves and
      drives the tool: **NIST IR 8547** is an *initial public draft* (2030/2035
      dates may shift); **HQC** (selected Mar 2025) and **FIPS 206 / FN-DSA**
      aren't final — when they get OIDs, `core/alg.py` + the deadline logic must
      follow. Low effort per update, high accuracy value.
- [ ] **Publish a discovery precision/recall corpus (field-first).** No FOSS
      crypto-*discovery* benchmark exists (CryptoAPI-Bench targets misuse). We
      already have the accuracy harness (#64) + the 51-OID oracle; a labeled,
      multi-surface ground-truth corpus turns "we believe it's accurate" into
      measured, reproducible proof — a real contribution to the field.

### Tier 2 — self-contained-compatible extensions (demand-driven)
- [ ] **Live QUIC sniffing** — QUIC Initial decryption exists for PCAP
      (`_quic.py`); extend `net.sniff.live` to do it on live UDP.
- [ ] **Binary crypto-constant expansion** — more S-boxes (DES SP-boxes,
      Camellia, SM4) + PQC NTT/Keccak constants for *static PQC* binaries.
- [ ] **pkilint-level cert profile validation** — FIPS key-size / key-usage
      checks beyond OID recognition (needs raw-SPKI DER parsing; `cryptography`
      won't parse PQC public keys) + IETF pqc-certificates DER vectors as e2e.

### Tier 3 — beyond the current mission (needs a design decision)
- [ ] **Migration assistance.** The tool *inventories*, it does not orchestrate
      migration (a deliberate boundary vs Keyfactor/Venafi). Moving into
      remediation execution is a scope change to decide, not drift into.
- [ ] **Continuous monitoring / trend view** — baselines + diff already exist; a
      time-series posture dashboard would operationalize them.

### Housekeeping
- [ ] Optional: back-fill git tags for v0.9.4–v0.9.10 (only v0.9.3 and v0.9.11
      are tagged/released; the v0.9.11 rollup covers the span).

---

## High-leverage (all shipped)

- [x] **SARIF renderer** — shipped as `renderers/sarif.py` + the `sarif`
      export slug; wired into `action.yml` for GitHub Code Scanning. ✅
- [x] **Domain-input web flow** — shipped: `--target` CLI option, the
      dashboard scan form's target field, and `ctx.server_target` plumbing
      through the network probes. ✅
- [x] **Per-finding remediation snippets** — shipped: typed PQC-replacement
      descriptors in `core/remediation.py` + per-language before/after
      snippets in `core/remediation_snippets.py`. ✅

## Medium-leverage (all shipped)

- [x] **Reverse-proxy / service-mesh config probes** — shipped:
      `fs.conf.{apache,envoy,haproxy,traefik,caddy,f5,netscaler}` +
      `k8s.mesh_{mtls,policy}`. ✅
- [x] **QRAMM compliance YAML** — shipped:
      `compliance/frameworks/qramm.yaml` (16 rules). ✅
- [x] **PCAP / pcapng ingestion** — shipped dependency-free as
      `probes/_pcap.py` + `fs.pcap.crypto` (incl. QUIC Initial decryption);
      no pyshark/scapy needed. ✅

## Coverage candidates (from 2026-07-21 3-pass research — see COMPETITIVE-LANDSCAPE.md)

These are the only self-contained-compatible techniques the *verified* field has
that pqcscan lacks (runtime call-tracing à la SandboxAQ is a deliberate non-goal
— it breaks the any-OS self-contained binary).

- [x] **Binary crypto-constant signatures** — `probes/_crypto_constants.py`
      (v0.9.6): 16 signatures (AES S-boxes, SHA/MD/Keccak round constants,
      ChaCha sigma, Blowfish P-array) detect static/stripped binaries the
      `.dynsym` linkage detection misses. Gated on "no library detected". ✅
- [x] **Passive PQC ClientHello group fingerprinting** — `net.sniff.live` +
      `fs.pcap.crypto` already flag offered PQC/hybrid groups (X25519MLKEM768,…);
      **v0.9.7** grades a `key_share` offer (actively negotiating → medium) above
      a bare `supported_groups` advertisement (low). No FOSS tool does this —
      JA4 records only the ext *type*, Zeek only the negotiated curve. ✅
- [x] **Cert PQC recognition accuracy** — **v0.9.7** added the 15 missing FIPS
      204/205 pre-hash OIDs (HashML-DSA/HashSLH-DSA, NIST-CSOR-verified) + a
      51-OID ground-truth recall oracle. ✅
- [x] **Native-vs-OQS OpenSSL version awareness** — `host.openssl.pqc_provenance`
      (v0.9.8) synthesizes `openssl version` + `list -providers` into a native /
      oqs-provider / none provenance verdict, per the UMBC survey requirement. ✅
- [~] **Cert PQC recognition recall** — `fs.cert.pqc_x509` now recognizes the full
      standardized surface (pure + pre-hash + composite + Falcon) via centralized
      `core.alg` (v0.9.9). *Remaining sub-item, deferred:* deeper **profile**
      validation (pkilint-level FIPS 203/204/205 key-size / key-usage checks)
      needs raw-SPKI DER parsing (`cryptography` won't parse PQC public keys) and
      the IETF-Hackathon/pqc-certificates DER corpus as end-to-end vectors — a
      worthwhile but self-contained follow-up.
- [x] **On-ramp signature algorithm recognition** — MAYO/SNOVA/CROSS/UOV/HAWK/
      SQIsign added to `core/alg.py` PQC-ready set (were classified INFO). ✅
- [x] **QUIC PQC probing** — `_quic.py` (v0.9.11): decrypts the QUIC Initial
      (RFC 9001 v1 / RFC 9369 v2 keys from the DCID, verified vs the RFC 9001 A.1
      vector) → CRYPTO-frame ClientHello → offered PQC groups, wired into
      `fs.pcap.crypto`. The category *no other FOSS tool covers*. ✅
- [ ] **JA4/JA4X TLS fingerprint emission** — *deferred, low priority.* A client-
      *correlation* fingerprint, not a PQC signal: our 2026-07-21 research
      confirmed JA4 records only the extension **type** code, so it adds no PQC-
      group info (which `net.sniff.live` already extracts directly). Correctness
      also requires matching the reference JA4 spec byte-for-byte with vectors.
- [ ] **Publish a discovery precision/recall corpus** — *deferred, data/release
      task (not code).* No FOSS ground-truth benchmark exists for crypto
      *discovery*; our accuracy harness (#64) + the 51-OID recall oracle (v0.9.7,
      now also exercising `fs.cert.pqc_x509`) are a start.

## Low-leverage

- [ ] **SCTP / DCCP / RTP / Telnet / TFTP probes** — only LiuYuancheng
      bothers with these. Mostly legacy / niche.

- [ ] **Tree-sitter rule density bump** — Hacker21-punk/pqscan has
      100+ static-code rules vs our ~8 tree-sitter probes per language.
      Worth widening if the user runs against polyglot codebases.
      ~3 days.

- [ ] **Hosted SaaS** — pqscan.io is a paid hosted scanner. We're
      open-source by design; flag if monetisation ever surfaces.

## Ideas / unverified

- [ ] **`wakaken/pqc-scan`** repo — page returned minimal content during
      the audit, possibly empty/abandoned. Re-check before doing
      anything inspired by it.

- [ ] **`pqc-enkripsi.citechsolutions.com.my`** — couldn't extract
      substantive content; if it's NACSA-aligned it might mirror our
      MyKripto/BUKUKERJA bundling.
