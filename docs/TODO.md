# pqcscan — backlog

Gaps surfaced by the 2026-05-05 coverage audit against 12 peer projects
(LiuYuancheng/Network_PQC_Attack_Resistance_Evaluator, cyberjez/PQC-Scanner,
csnp/cryptoscan, Hacker21-punk/pqscan, anvilsecure/pqcscan, pqcworld.com,
checkpqc.app, wiz.io/pqc-tester, pqscan.io, et al.).

We already cover the majority of what they do; the items below are the
gaps worth filling, ranked by leverage.

## High-leverage

- [ ] **SARIF renderer** (`renderers/sarif.py` + `cli/export.py` slug
      `sarif`). Unlocks GitHub Code Scanning integration so findings
      surface natively on PRs. ~2h. Has parity with csnp/cryptoscan,
      Hacker21-punk/pqscan, pqaudit.

- [ ] **Domain-input web flow** — let a user paste `example.com` on the
      dashboard and run network probes against that target (instead of
      always scanning the local host). Mirrors checkpqc, wiz pqc-tester,
      pqscan.io. New route + `--target` CLI option. ~1 day.

- [ ] **Per-finding remediation snippets** — currently `Finding.remediation`
      is free-form. Add an enum-tagged "PQC-replacement" field
      (e.g. RSA-2048 → ML-KEM-768; ECDSA-P256 → ML-DSA-65). pqaudit and
      cryptoscan both ship this. ~1 day.

## Medium-leverage

- [ ] **Reverse-proxy / service-mesh config probes** — Apache, Envoy,
      Istio, HAProxy, Traefik. Same pattern as `app.nginx.jwt_validation`.
      Hacker21-punk/pqscan covers all of these. ~1 day for 5 probes.

- [ ] **QRAMM compliance YAML** (`compliance/frameworks/qramm.yaml`).
      Quantum Readiness Assurance Maturity Model — referenced by
      csnp/cryptoscan. Pure data work, no Python. ~4h.

- [ ] **Wireshark .cap / pcapng ingestion** — read packet captures
      offline and emit findings (TLS handshake → cipher suite, SSH KEX,
      etc.). LiuYuancheng's tool does this end-to-end. Adds `pyshark`
      or `scapy` dep. ~2 days.

## Coverage candidates (from 2026-07-21 3-pass research — see COMPETITIVE-LANDSCAPE.md)

These are the only self-contained-compatible techniques the *verified* field has
that pqcscan lacks (runtime call-tracing à la SandboxAQ is a deliberate non-goal
— it breaks the any-OS self-contained binary).

- [x] **Binary crypto-constant signatures** — `probes/_crypto_constants.py`
      (v0.9.6): 16 signatures (AES S-boxes, SHA/MD/Keccak round constants,
      ChaCha sigma, Blowfish P-array) detect static/stripped binaries the
      `.dynsym` linkage detection misses. Gated on "no library detected". ✅
- [ ] **[TOP] Passive PQC ClientHello group fingerprinting** — parse the TLS
      ClientHello `supported_groups`/`key_share` in `net.sniff.live` to flag
      which PQC/hybrid groups (X25519MLKEM768, …) an endpoint offers. **The
      2026-07-21 gap pass confirmed NO FOSS tool does this**: JA4 records only
      the extension *type* code, not contents; Zeek `ssl.log` logs only the
      *negotiated* curve. Genuine whitespace + top differentiator.
- [ ] **Native-vs-OQS OpenSSL version awareness** — distinguish native PQC
      (OpenSSL ≥3.5, Apr 2025) from `oqs-provider`-on-3.x add-on, per the UMBC
      survey requirement. Version-aware linkage classification in
      `fs.binary.crypto` / host lib detection.
- [ ] **Deeper cert PQC profile validation + ground-truth vectors** — pkilint
      (DigiCert) does FIPS 203/204/205 key-size/key-usage validation beyond our
      OID recognition in `fs.cert.pqc_x509`; adopt the **IETF-Hackathon/
      pqc-certificates** ML-DSA/ML-KEM/SLH-DSA/composite test corpus as a
      ground-truth accuracy test.
- [x] **On-ramp signature algorithm recognition** — MAYO/SNOVA/CROSS/UOV/HAWK/
      SQIsign added to `core/alg.py` PQC-ready set (were classified INFO). ✅
- [ ] **Publish a discovery precision/recall corpus** — no FOSS ground-truth
      benchmark exists for crypto *discovery* (CryptoAPI-Bench targets misuse).
      Our accuracy harness (#64) + a labeled corpus would be a field first.

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
