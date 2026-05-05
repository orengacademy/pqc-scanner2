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
