# pqcscan — PQC coverage roadmap ("cover everything possible")

**Date:** 2026-06-22 · **Baseline:** v0.6.9 (114 probes) · **Method:** 25-agent workflow — per-domain "everything possible" enumeration → repo-grounded gap audit → synthesis.
**Headline:** **70 capabilities covered, 254 missing/proposed across 12 domains.** pqcscan is a strong PQC-readiness scanner; this maps what it would take to maximize coverage of what a scanner *can* own.

## Delivery progress (updated 2026-06-23) — 114 → 143 probes

**Phase 0 — complete.** WireGuard PSK severity fix · `host.crypto_policies.profile` · `host.ssh.binary_caps` · `host.krb5.config` · `host.openssl.version` · `fs.ssh.host_keys`.

**Phase 1 — complete.** `fs.keyref.cloud` (AWS/Azure/GCP KMS + PKCS#11) · `fs.keystore.pkcs12` · `fs.cert.csr` · `fs.cert.pkcs7` · `fs.cert.expiry_horizon` (CNSA-2.0 HNDL, CA-cert-skip) · `fs.cert.privkey_encrypted` · `fs.keystore.jks` (magic-byte inventory; full per-entry parsing deferred — needs `pyjks`).

**Phase 2 — keystone landed + partial.** `net.tls.kex_groups` (raw-TLS KEX-group enumeration, no OS `ssl` — closes the #1 HNDL gap) · `net.tls.versions` (raw-socket version sweep). *Still open:* full served-chain `signatureAlgorithm` (TLS 1.3 encrypts the Certificate → needs handshake completion / a TLS 1.2 cleartext path), QUIC (needs `aioquic`).

**Phase 3 — substantial progress.** `host.openssl.groups` · `k8s.mesh.policy` · `fs.cert.chain` (AKI/SKI assembly + key-reuse) · `host.openssl.fips_state` · `host.kernel.crypto_registry` · `host.gnutls.config` · `host.nss.policy`. *Still open:* `net.kerberos.etypes` (L, ASN.1 AS-REQ), real `net.ike.transforms` (L), TLS resumption/revocation, passive PCAP, service-mesh SPIFFE deep parse.

**Decision-gated / deferred:** `pyjks` (full JKS), `aioquic` (QUIC), tree-sitter grammars (Phase 4 app-code AST rebuild). **Phase 4–5** (classifier hardening, ROCA/Debian key-health, chain blast-radius, kernel/TPM/smartcard long-tail) largely untouched.

**Bug found + fixed during delivery:** `net.tls.*` `_resolve_target` crashed the scan on a malformed target (`applies()` runs outside the runner's try/except) — now gates off safely.

## Three structural ceilings (recur in every domain)

1. **Network probes ride the OS `ssl` stack** — they see only the *negotiated* cipher + *leaf* cert (`_tls_probe.py` uses `getpeercert(binary_form=True)`). Offered/selected **KEX groups**, the **full served chain's `signatureAlgorithm`**, QUIC, real IKE SA transforms, Kerberos etypes are invisible. → classical ECDHE/FFDHE **harvest-now-decrypt-later** exposure is largely undetected.
2. **App/code layer is regex-only** despite `code.ts.*` ("tree-sitter") naming — no AST, no import/alias binding, no constant folding; misses curves, Ed25519/X25519, OAEP-vs-PKCS1v15, AEAD modes, PQC libs.
3. **Classifier (`core/alg.py`, 97 lines)** is a small prefix/regex map — hardcoded OID table missing SLH-DSA/Falcon/composite/RSA-PSS, no weak-key health, no HNDL/2030-2035 deadline logic.

**The keystone:** a **self-contained raw-TLS handshake engine** (no OS `ssl` dependency) that enumerates `supported_groups`/`key_share`, the full Certificate chain with per-cert `signatureAlgorithm`, and `signature_algorithms`/`CertificateRequest`. One engine closes the biggest network gap *and* feeds chain/expiry work in PKI.

## Coverage matrix

| Domain | Est. | State | Headline gap |
|---|---:|---|---|
| network-transport | 55% | partial | OS-ssl-stack only sees negotiated cipher + leaf; no KEX-group/chain-sigalg/QUIC/IKE-SA/etype enumeration |
| host-os | 60% | partial | No crypto-policies profile, no binary-capability probes (`ssh -Q`, `openssl version -a`), no krb5/IPsec/GnuTLS/NSS |
| filesystem-pki | 50% | partial | `fs.cert.x509` reads SPKI only (not sigalg); no chain assembly; PKCS#12/JKS/CSR/PKCS#7/encrypted-key unparsed |
| app-code | 30% | **weak** | All `code.ts.*` regex-only; no AST/alias/constant-folding; narrow primitives |
| classifier-core | 55% | partial | `alg.py` OID table missing SLH-DSA/Falcon/composite/PSS; no HNDL/deadline; coarse AES/SHA tiers |
| ot-ics | 65% | strong | Good breadth (15 protocols); depth-limited — DTLS/TLS reuses leaf-only path; no PKINIT/device-PKI lifecycle |
| cloud-kms-keyref | 10% | **absent** | No AWS/Azure/GCP KMS, `pkcs11:` URIs, SoftHSM, TPM key-blob discovery — largest missing enterprise asset class |
| sbom-supplychain | 70% | strong | Packages inventoried but not mapped to the crypto primitives / PQC support they ship |
| compliance-reporting | 70% | strong | No timeline-aware deadline scoring (CNSA2.0 2030/2035, HNDL) or chain blast-radius prioritization |

## Phased sequence

- **Phase 0 — config/binary quick wins** (days, S-effort, no new deps): crypto-policies profile; `ssh -Q` + `sshd -T`/Include-Match expansion; `openssl version -a`; **WireGuard PSK** detection; `krb5.conf` parse; on-disk SSH key-blob parsing. Immediate accuracy + false-negative reduction.
- **Phase 1 — asset-discovery breadth** (M–L, library-based): **PKCS#12/PFX + JKS/JCEKS** keystores; **cloud-KMS/Key-Vault/PKCS#11-URI** key-references; encrypted-privkey/CSR/PKCS#7-CMS parsing; **cert expiry-vs-deadline / HNDL horizon** scoring. Surfaces the biggest invisible asset classes; turns inventory into prioritized risk.
- **Phase 2 — raw-TLS handshake engine + dependents** (L, keystone): group/`key_share` enumeration, full-chain `signatureAlgorithm`, `signature_algorithms`/mTLS, standalone ML-KEM, resumption/version-sweep/revocation.
- **Phase 3 — deep transport** (L–XL): real IKE SA transforms + IPsec config/xfrm; Kerberos etype + PKINIT; QUIC/HTTP-3; passive PCAP; service-mesh deep policy + cert-manager issuers; DTLS 1.3.
- **Phase 4 — source-code credibility + classifier hardening** (XL + M): tree-sitter rebuild of `code.ts.*`; `alg.py` OID/tier/deadline hardening; chain assembly + weak-key health (ROCA/Debian/batch-GCD); content-sniffing/embedded-cert extraction.
- **Phase 5 — long-tail** (low value): kernel/`/proc/crypto`/RNG/TPM-sealed/platform-keystore; live smartcard/PIV; SMB-over-QUIC; PAM hashing; eCryptfs/keyring/IMA-EVM.

## Prioritized backlog

| Item | Domain | Value | Effort |
|---|---|---|---|
| Raw-TLS handshake engine (groups/`key_share`, classical ECDHE/FFDHE → HNDL-HIGH) | network | critical | L |
| Full served-chain `signatureAlgorithm` + `signature_algorithms`/mTLS; add sigalg to `fs.cert.x509` | pki | critical | L |
| PKCS#12/PFX + JKS/JCEKS keystore probes (chain, key alg, weak-MAC); scan JRE cacerts | pki | critical | L |
| Cloud KMS / Key Vault / `pkcs11:` URI / HSM key-reference discovery in configs + IaC | cloud | critical | L |
| Cert expiry-vs-deadline / HNDL-horizon scoring vs CNSA2.0 2030/2035 calendar | compliance | critical | M |
| System crypto-policies profile probe (`/etc/crypto-policies`) | host | high | S |
| Binary-capability probes: `ssh -Q`, `openssl version -a`, `sshd -T` effective config | host | high | S |
| On-disk SSH key + authorized_keys/known_hosts blob parsing (type + bit length) | pki | high | M |
| Real IKE SA transform enumeration (RFC 9370 ADDKE ML-KEM, RFC 8784 PPK) + IPsec config/xfrm | network | high | L |
| Kerberos etype enumeration + PKINIT (ASN.1 AS-REQ) + `krb5.conf` parse | network | high | L |
| WireGuard PSK presence detection (corrects severity — only PQ-hardening knob) | network | high | S |
| Encrypted privkey + CSR + PKCS#7/CMS + DER/OpenSSH privkey support | pki | high | M |
| Tree-sitter rebuild of `code.ts.*` (AST, alias binding, broadened primitives) | app-code | high | XL |
| Cert chain assembly + weak-key health (AKI/SKI graph, ROCA, Debian blocklist) | pki | high | L |
| FIPS module activation state + GnuTLS/NSS policy probes | host | high | M |
| QUIC / HTTP-3 handshake analysis (aioquic) | network | high | XL |
| OpenSSL host KEX-group + sigalg policy enumeration | host | medium | M |
| Service-mesh deep policy + cert-manager issuer key-algorithm inventory | network | medium | M |
| Passive PCAP crypto extraction (TLS/SSH/IKE/QUIC offered+negotiated) | network | medium | L |
| TLS version sweep + resumption/0-RTT + OCSP/CRL/CT revocation-infra sigalgs | network | medium | M |
| Classifier hardening: complete OID table, finer tiers, deadline/HNDL hook | classifier | medium | M |
| Content-sniffing unlabeled cert/key files + embedded (JAR/WAR/APK/OCI) extraction | pki | medium | L |
| Kernel/`/proc/crypto` + RNG/DRBG + TPM-sealed + platform-keystore inventory | host | medium | M |
| Live smartcard/PIV/OpenPGP-card + TPM mechanism enumeration | host | low | L |
| SMB-over-QUIC, DTLS 1.3 generalization, PAM hashing, eCryptfs/keyring/IMA-EVM | host | low | M |

## Fundamentally out of a scanner's scope (keeps "everything possible" honest)

- **Migration execution / remediation** — rotating certs, reconfiguring TLS/SSH/IPsec, rekeying. Inventory + prioritize, don't change.
- **Runtime / policy enforcement** — blocking handshakes, admission control, WAF/proxy gating. That's enforcement infra.
- **QKD / quantum-network hardware** — out of band for a software scanner.
- **Key-management / KMS lifecycle ops** — generate/escrow/rotate/wrap/destroy key material, HSM admin. Discover key *references* + specs; never read/extract private material.
- **Breaking crypto / exfiltrating secrets** — weak-key checks use public moduli only.
- **Vuln exploitation / pen-testing** — posture assessment, not exploit chains (consume SCA output instead).
- **Acting as a CA / RNG** — inventory CA trust + RNG config; never issue or sign.
- **Continuous monitoring / SIEM** — point-in-time CBOM snapshots feed downstream platforms; pqcscan isn't the pipeline.
