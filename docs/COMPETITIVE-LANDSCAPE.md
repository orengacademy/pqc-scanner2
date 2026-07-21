# PQC-scanner competitive landscape (2025–2026)

Synthesised from two deep-research passes (GitHub + web crawl, adversarial
claim verification). Every tool cited with its URL. Use this to position
pqcscan and to source the next coverage ideas.

## The field splits into three families

1. **Active on-the-wire scanners** — live TLS/SSH handshakes.
2. **Static / inventory scanners** — parse source (AST or regex), filesystems,
   images, certs, dependencies → emit a CBOM.
3. **Passive network sensors** — read SPAN/TAP traffic, no handshake.

pqcscan spans **all three** plus host config, filesystem keys, and code — the
whitespace the research confirmed no single open-source tool fills.

## Master catalog

### Open-source · active network scanners
| Tool | URL | Lang / License | Technique | Note |
|---|---|---|---|---|
| anvilsecure/pqcscan | https://github.com/anvilsecure/pqcscan | Rust · BSD-2 | advertised-only (no full handshake) | Jul 2025; TLS+SSH; network-only |
| QuantaSeek | https://github.com/Mehrn0ush/QuantaSeek | Rust · rustls | **active** TLS 1.2/1.3, parses ServerHello | ML-KEM/hybrid; network-only |
| Hacker21-punk/pqscan | https://github.com/Hacker21-punk/pqscan | — | — | niche, ~v0.1, README-only |
| cyberjez/PQC-Scanner | https://github.com/cyberjez/PQC-Scanner | — | — | niche, no license |
| wakaken/pqc-scan | https://github.com/wakaken/pqc-scan | — | — | niche |
| pqswitch/scanner | https://github.com/pqswitch/scanner | — | — | niche |
| testssl.sh / sslscan / sslyze / CryptoLyzer | (homepages) | — | active handshake + grading | TLS config graders w/ some PQC awareness |

### Open-source · code / CBOM generators
| Tool | URL | Lang | Technique | Output |
|---|---|---|---|---|
| PQCA CBOMkit suite (sonar-cryptography, cbomkit, -action, -theia) | https://github.com/PQCA | Java/multi | **AST** | CBOM 1.6; ex-IBM → Linux Foundation |
| csnp/cryptoscan | https://github.com/csnp/cryptoscan | Go | regex + confidence | CBOM · **SARIF** · CSV · QRAMM/FIPS 203-206/OMB M-23-02 |
| IBM Research Cryptoscope | https://arxiv.org/html/2503.19531v1 | — | **ANTLR AST + program slicing** | CBOM + CWE |
| jimbo111/open-quantum-secure | https://github.com/jimbo111/open-quantum-secure | Go | 7 engines (config/binary/tls-probe/ssh-probe/**ct-lookup**/ast-grep/semgrep) | CBOM 1.7 + SARIF + HTML/CSV; CNSA 2.0 |
| cbomkit / sonar-cryptography / -action | https://github.com/cbomkit/cbomkit | Java/multi | AST | CBOM (IBM's toolkit, own `cbomkit` org) |
| OWASP **cdxgen** | https://github.com/CycloneDX/cdxgen | multi (20+) | SBOM + crypto cataloguing | CycloneDX SBOM/**CBOM**; mainstream, very active |
| epap011/Crypto-Scanner-PQC | https://github.com/epap011/Crypto-Scanner-PQC | — | code scan | vuln + PQC-readiness (small) |
| mbennett-labs/crypto-scanner | https://github.com/mbennett-labs/crypto-scanner | — | CLI code scan | quantum-vulnerable crypto (small) |
| CryptoGuard / CogniCrypt | https://arxiv.org/pdf/1806.06881 · (Eclipse) | Java | crypto-API-misuse SAST | not PQC-inventory |

### Open-source · host / filesystem inventory (deep)
| Tool | URL | Scope | Output |
|---|---|---|---|
| **CipherIQ/cbom-generator** | https://github.com/CipherIQ/cbom-generator | Linux host: certs, keys, algorithms, crypto libs; **embedded Linux** (Yocto/Buildroot/OpenWrt) | CycloneDX **1.6/1.7 CBOM** + PQC classification. Linux-only; no network/code/SBOM breadth. |

### Commercial crypto-agility platforms (vendor-claimed; not independently benchmarked)
| Vendor | Note |
|---|---|
| **PQ Crypta** Discovery Agent — https://pqcrypta.com/discovery | **Closest functional analog to us.** Rust agent, **fully offline on-host**: disk certs/keys, SSH dirs, live TLS, **DB columns**, **F5/NetScaler appliances**, hardcoded weak crypto in code → CBOM + inventory. Closed source. |
| Keyfactor (absorbed **InfoSec Global AgileSec** + **Quantum Xchange CipherInsights**, May 2025) | host/binary/source discovery + passive sensor → CBOM; most feature-complete single vendor |
| IBM Quantum Safe Explorer / Guardium / ADDI | AST source scan + network posture; IBM authored CBOM |
| SandboxAQ AQtive Guard (absorbed Cryptosense) | multi-method: passive net + runtime hooks + FS + source |
| **HCL BigFix** Quantum Readiness Scanner | BigFix add-on agent; certs + private keys, ML-KEM/SLH-DSA detection, remote scan + reporting |
| **QuantumGate** Crypto Discovery | system + application + network + cloud sensors |
| **Q-CORE Systems** | TLS config/cipher/cert + PQC-readiness platform |
| Wiz PQC Readiness + Tester | agentless cloud-API + active external handshake |
| Palo Alto PAN-OS Quantum Security | passive+active NGFW sensor (IKEv2) |
| DigiCert · Venafi/CyberArk · QuSecure | active net scan + agent/CA-sync; various CBOM roadmaps |

### Hosted single-domain "edge" scanners (SaaS, point-at-a-URL)
| Tool | URL | Technique | Note |
|---|---|---|---|
| PostQ | https://postq.dev | active TLS handshake; cloud/k8s in private preview | 0-100 score + PDF; closed |
| PQScan.io | https://pqscan.io | active TLS check (host:port) | risk level; EN + zh-TW; closed |
| Cyberzero PQC Edge | https://scan.cyberzero.io | **passive** (browser-equivalent) + DNS/DNSSEC + CT logs | brief; Pro monitoring; closed |

### Indexes & curated lists (browse everything)
- **Santander PQCTools** — https://github.com/Santandersecurityresearch/PQCTools — the authoritative registry (CADI = discovery/inventory, PQCI = implementation).
- awesome lists: https://github.com/veorq/awesome-post-quantum · https://github.com/qtonicquantum/awesome-pqc · https://github.com/gauravfs-14/awesome-pqc
- GitHub topics: `cryptographic-inventory`, `crypto-scanner`, `post-quantum-security`.

### Standards / spec
- CycloneDX **CBOM** — https://cyclonedx.org/capabilities/cbom/
- **PQCA** (Post-Quantum Cryptography Alliance) — https://github.com/PQCA
- NIST NCCoE *Migration to PQC* — https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc

## Most capable / active (2025–2026)
1. **PQCA CBOMkit** — the de-facto open CBOM toolchain (AST).
2. **csnp/cryptoscan** — broadest OSS code scanner with CBOM+SARIF+compliance.
3. **jimbo111/open-quantum-secure** — only OSS tool spanning code **and** live
   TLS/SSH in one CBOM+SARIF pipeline (breadth self-reported).
4. **QuantaSeek** — real PQC TLS handshakes (vs advertised-only pqcscan).
5. **IBM Cryptoscope / Quantum Safe Explorer** — strongest AST/slicing precision.

## Whitespace — where pqcscan (this project) sits
> Verified conclusion: *"No single verified open-source tool fully unifies
> network + host config + filesystem certs + code + SBOM + container into one
> CBOM+SARIF+compliance pipeline."*

pqcscan is that tool: all six surfaces + binary + cloud-KMS + CBOM + SARIF +
19 compliance frameworks with CNSA-2.0/IR-8547 deadlines + **per-finding
confidence scoring** (which the research found *no vendor documents formally*)
+ bilingual EN/MS reports.

The one genuine functional peer is the **commercial, closed-source PQ Crypta
Discovery Agent** (offline on-host, multi-surface, CBOM). We match its design
and add SBOM-dependency mapping, compiled-binary scanning, containers, SARIF,
19-framework compliance, confidence, and bilingual reports — all open-source.
The two surfaces PQ Crypta had that we lacked are now closed:

- **Certificate Transparency lookup** (crt.sh) — shipped `net.ct.crtsh`.
- **Compiled-binary crypto** (ELF/PE/Mach-O) — shipped `fs.binary.crypto`.
- **Live cloud KMS** (AWS/Azure CLI) — shipped `host.cloud_kms`.
- **DB-column cert/key material** — shipped `fs.db.crypto`.
- **Network appliances (F5 BIG-IP / Citrix NetScaler)** — shipped
  `fs.conf.f5` + `fs.conf.netscaler`.

The two remaining capability gaps versus the live-sensor and AST vendors are
now closed too (v0.8.6), within the self-contained constraint:

- **Live passive / SPAN sensing** (SandboxAQ, Palo Alto PAN-OS, Cyberzero) —
  shipped **`net.sniff.live`** + `pqcscan sniff`: pure-stdlib `AF_PACKET` raw
  capture, no libpcap/scapy. We now sense live traffic *and* keep the offline
  `fs.pcap.crypto` path.
- **Source-code precision** — **Python** now uses a real stdlib-`ast` engine
  (`core/pyast.py`): comment/string-immune, import/alias-resolved. Go/Java/
  JS/PHP/Rust gain a comment/string suppressor (`core/srcstrip.py`).

Deliberately *not* adopted: **native multi-language AST** (sonar-cryptography /
Cryptoscope grammars for non-Python) — they ship platform-specific compiled
artifacts that would break the any-OS self-contained binary. Python AST is
pure-stdlib so it *was* adopted; for the other languages the comment/string
suppressor + confidence model down-rank the residual regex false positives.
Managed CA-lifecycle / migration orchestration (Keyfactor, Venafi) is out of
scope by design — pqcscan produces the inventory; it does not run the migration.

## 2026-07-21 research refresh (verified deltas)

A third deep-research pass (19 sources, 25 claims adversarially verified 3-0,
0 refuted). Additive to the tables above; nothing below contradicts them.

### Standards have converged — this is now the stable substrate
- **Output format:** CycloneDX **CBOM is standardized as ECMA-424**. Crypto
  assets became first-class in **1.6 (2024)**; **1.7 adds a Cryptography
  Registry** to resolve algorithm-name synonyms. pqcscan already emits **1.7**,
  ahead of the reference generator (CBOMkit, still 1.6).
- **Regulatory clock — NIST IR 8547** (initial public draft): 112-bit
  public-key crypto (RSA, ECDSA, DH/ECDH, RSA-KEM) **deprecated after 2030,
  disallowed after 2035**; all quantum-vulnerable public-key crypto disallowed
  after 2035. Targets: exactly three finalized standards — **FIPS 203 ML-KEM,
  204 ML-DSA, 205 SLH-DSA** (FIPS 206/FN-DSA + HQC still pending). pqcscan's
  `core/remediation.py` deadline logic already encodes this.
- **HNDL is the policy driver:** NIST states it will **prioritize migrating
  key-establishment in interactive protocols (TLS, IKE)**, potentially *before*
  the 2035 date. This validates HNDL-weighted prioritization + readiness
  scoring (pqcscan's HNDL flags, `core/migration_score.py`, QRAMM).

### The three CBOM-accuracy obstacles (IBM, Eurocrypt 2026) — and our answer
Accurate crypto discovery is bounded by three documented obstacles. They are
exactly the false-positive sources a precise scanner must attack:
1. **Naming ambiguities** → CycloneDX 1.7 Registry; pqcscan normalizes via
   `core/alg.py` OID/name table.
2. **Configuration-driven cryptography** (crypto is a runtime outcome of
   negotiation) → pqcscan's live `net.sniff.live` + handshake probes observe
   what is *actually* negotiated, not just what source declares.
3. **Provision vs consumption** (present ≠ used) → **this is the field's #1
   unsolved obstacle, and pqcscan's v0.9.1 reachability layer
   (`fs.binary.crypto` `.dynsym` invoked/linked-only) is a direct attack on
   it.** No verified OSS tool addresses this. Lead with it in positioning.

### New tools / facts from this pass
| Tool | Category | Delta |
|---|---|---|
| **sbom-tools** (github.com/sbom-tool/sbom-tools) | CBOM **grader** (consumer, Rust) | Parses CycloneDX 1.6/1.7 cryptoProperties → PASS/FAIL vs **CNSA 2.0 + NIST IR 8547** + 8-category CBOM quality score. Grades inventories; doesn't generate them. Analog to pqcscan's compliance engine. |
| **sslyze** | TLS prober | **Measured PQC blind spot:** arXiv 2605.02978 ("Observability for PQ TLS Readiness") — sslyze detected **0 hybrid targets vs 70** via dual-probe. Concrete evidence that classical TLS graders miss PQC. |
| **testssl.sh** | TLS prober | PQC support **landed in v3.2** (6 KEMs + ML-DSA); more in 3.3dev. The classic scanner is now PQC-aware — parity pressure on the `net.tls.*` family. |

### Reference frameworks worth mapping our coverage against
- **IETF draft-liu-cadi** — Cryptographic Asset Discovery & Inventory: an
  emerging **taxonomy of discovery methods** (static/SAST, binary/image,
  network probe, passive). Good external checklist for "do we cover every
  method." (pqcscan spans all four.)
- **CISA** *Strategy for Migrating to Automated PQC Discovery and Inventory
  Tools* (2024) — the buyer-side requirements doc; useful for framing README.

### Commercial vendors — verified primary-source detail (2026-07-21 pass)
A dedicated commercial pass. Of ~20 named vendors, only **four** produced claims
that survived adversarial verification against primary sources; the rest had no
verifiable primary detail (marketing-only). **No pricing was verifiable for any
vendor.**

| Vendor | Modalities (verified) | CBOM | Runtime/binary? | Orchestration? |
|---|---|---|---|---|
| **SandboxAQ AQtive Guard** (absorbed Cryptosense) | 9 named sensors: Java/Python/.NET/OpenSSL/PKCS#11 **runtime tracers**, Filesystem Scanner, **Java Bytecode Scanner**, Network Analyzer (**live + PCAP upload**), PKCS#11 Fuzzer | **Ingests** CycloneDX 1.4/1.6 (export format unconfirmed) | **Yes — genuine runtime reachability** (live crypto-lib call tracing in production) | **Yes — full**: key rotation, algo/protocol switching, blast-radius simulation, JIRA/GitHub remediation. Maps CNSA 2.0 + FIPS 203/204/205 (not IR 8547/BSI/ANSSI on page). |
| **IBM Quantum Safe Explorer** | Source-code SAST (Sonar Cryptography plugin / CBOMkit-hyperion) | **Exports CycloneDX** (IBM upstreamed its CBOM model into 1.6/ECMA-424) | No (source-centric) | Discovery/posture |
| **Keyfactor AgileSec** (= acquired InfoSec Global AgileSec Analytics) | **Compiled-binary analysis** of 3rd-party/OS binaries w/o source + multi-modality via lightweight sensors | (not confirmed) | **Yes — binary** | Discovery + CA lifecycle |
| **Qinsight Atlas** | Cloud + code + endpoint sensors + API | CBOM (**format unspecified** — likely proprietary) | No passive-net/PCAP/binary | Posture |

**No surviving verified claims** for: PQShield, Venafi/CyberArk Machine Identity,
DigiCert Trust Lifecycle/Device Trust, Quantum Xchange CipherInsights, Entrust,
Thales CipherTrust, IBM Guardium Quantum Safe, Wiz, Qualys, Tenable, Palo Alto,
Cisco, Cloudflare, ISARA, Utimaco, AppViewX, Microsoft crypto-agility. (Absence
of *verified* claims ≠ absence of product; it means no primary detail survived.)

**Competitive read:** SandboxAQ AQtive Guard is the most capable verified
platform — and the only one doing **runtime reachability via live call tracing**,
a strictly deeper answer to provision-vs-consumption than pqcscan's *static*
`.dynsym` reachability. That's the one capability tier above us. Everything else
(multi-surface discovery, CBOM, compliance breadth) we match or exceed in the
open, and no verified vendor matches our surface breadth + 19 frameworks +
bilingual reports + self-contained any-OS binary.

### FOSS coverage checklist — what a "complete" scanner fingerprints (2026-07-21 pass)
An exhaustive-FOSS pass (partial: verification budget covered SAST + network +
precision technique; binary/firmware, cert/PKI, PCAP/JA4, SBOM/CVE-mapper
categories were not re-confirmed — the tables above already cover those).
Actionable, verified take-aways:

- **PQC-library presence signals** a readiness scanner should fingerprint
  (oqs-provider ALGORITHMS.md): KEMs **ML-KEM, FrodoKEM, BIKE, HQC**; signatures
  **ML-DSA, Falcon, SLH-DSA, MAYO, CROSS, SNOVA, UOV**; hybrids **X25519MLKEM768,
  SecP256r1MLKEM768, SecP384r1MLKEM1024**. → pqcscan's `core/alg.py` now
  recognizes all of these including the on-ramp signatures (MAYO/SNOVA/CROSS/
  UOV/HAWK/SQIsign added 2026-07-21); TLS hybrid groups covered in
  `net.tls.kex_groups`.
- **Native OpenSSL 3.5 PQC vs OQS-provider-on-3.x** is a required distinction
  (native landed Apr 2025; OQS since 2022). *Coverage idea:* version-aware
  detection so an OpenSSL-3.5+ linkage counts as native PQC-capable vs a
  `liboqs`/`oqsprovider` linkage as add-on. **Not yet done — candidate.**
- **CSNP CryptoDeps** (github.com/csnp/cryptodeps) — a new dep-analysis (SCA)
  tool classifying deps VULNERABLE/PARTIAL/SAFE → SARIF/CBOM. Analog to our
  `sbom.*`/`cve.osv_offline` path.
- **Precision technique + benchmark (the accuracy story):** the academic
  **CryptoGuard** (flow/context/field-sensitive forward-backward slicing) cut
  false alerts 76–80% and hit **98.61% precision** on 46 Apache projects, and
  open-sourced **CryptoAPI-Bench** (112→171 ground-truth cases) — the only FOSS
  ground-truth corpus, though it targets crypto-API-*misuse*, not *discovery*.
  **There is NO discovery/inventory precision-recall benchmark in FOSS** — a
  genuine field gap. pqcscan's own accuracy-benchmark harness (PR #64) is ahead
  of the field here; publishing a labeled discovery corpus would be a first.

### Coverage / gap matrix — pqcscan vs the union of the field
| Technique | Best-in-field | pqcscan | Gap? |
|---|---|---|---|
| Source SAST (AST) | CBOMkit (Java/Py/Go AST), CryptoGuard (slicing) | Python real `ast`; others regex+string-strip+confidence | Native multi-lang AST deliberately not adopted (breaks self-contained binary) |
| Network TLS/SSH probe | pqcscan(anvil)/testssl.sh/QuantaSeek | `net.tls.*` incl. live handshake + KEX groups | ✅ covered |
| **Binary linkage** | Keyfactor AgileSec | `fs.binary.crypto` (ELF/PE/Mach-O) + **`.dynsym` reachability** | ✅ + reachability (rare) |
| **Runtime call tracing** | **SandboxAQ AQtive Guard** | static `.dynsym` proxy only | ⚠️ **the one tier above us** — runtime hooks break self-contained/any-OS premise |
| Binary crypto **constants** (S-box/YARA) | capa/find-crypt (generic) | ✅ `_crypto_constants.py` (v0.9.6) — 16 sigs, gated on no-linkage | ✅ covered (catches static Go/Rust/stripped) |
| Passive PCAP | SandboxAQ, `fs.pcap.crypto` | `fs.pcap.crypto` + `net.sniff.live` | ✅ covered |
| **Passive PQC key_share/supported_groups fingerprint** | **nobody** — JA4 records ext *type* only (`000a`/`0033`), not contents; Zeek `ssl.log` logs only the negotiated curve | ✅ **`net.sniff.live` + `fs.pcap.crypto`** already parse ClientHello `supported_groups`+`key_share` and flag offered PQC/hybrid groups; **v0.9.7** grades a `key_share` offer (actively negotiating → medium) above a bare advertisement (low) | ✅ covered — **ahead of the whole field** |
| Cert/PKI PQC | CryptoScan, zlint | `fs.cert.*` + `net.ct.crtsh` | ✅ covered |
| CBOM output | CBOMkit (1.6) | CycloneDX **1.7** | ✅ ahead |
| SARIF / CI gate | CryptoScan | SARIF 2.1.0 + `--fail-on` + Action | ✅ covered |
| Dep/CVE→crypto | CryptoDeps, Grype/Trivy | `sbom.*`, `cve.osv_offline` | ✅ covered |
| Compliance mapping | sbom-tools (2 frameworks) | **19 frameworks** | ✅ ahead |
| On-ramp algo recognition | oqs-provider list | `core/alg.py` (incl. MAYO/SNOVA/CROSS/UOV as of today) | ✅ now covered |
| Native-vs-OQS OpenSSL distinction | UMBC survey requirement | ✅ `host.openssl.pqc_provenance` (v0.9.8) — native/oqs-provider/none verdict | ✅ covered |
| Discovery precision benchmark | none in FOSS (CryptoAPI-Bench is misuse) | own harness (#64) | ✅ ahead; could publish a corpus |

**Net:** the only capability the *verified* field has that pqcscan lacks and
can't adopt is **runtime call tracing** (SandboxAQ) — incompatible with the
self-contained/any-OS binary premise, so a deliberate non-goal. Binary
crypto-constant signatures shipped v0.9.6; passive PQC group fingerprinting
turned out to be **already covered** (`net.sniff.live`/`fs.pcap.crypto`) and was
*sharpened* in v0.9.7 (key_share offers graded above advertisements) — a
whitespace no FOSS tool fills. The remaining candidates are ranked below.

## 2026-07-21 gap-closing passes (commercial + FOSS categories)

Two targeted follow-up passes closed the categories the earlier passes left
unverified. (The FOSS pass's final synthesis agent returned placeholder text —
findings below were recovered from the run journal; all are 3-0 verified claims
against primary sources.)

### Commercial — the previously-unverified vendors
| Vendor | Modality (verified) | CBOM | Binary/runtime? | Orchestration? |
|---|---|---|---|---|
| **DigiCert Trust Lifecycle Manager** | Certificate/PKI discovery (network/cloud/endpoint scan, CT logs, CA import) | ✗ none documented | No | **Yes** — PQC migration flows (Premium) |
| **CyberArk (Venafi) Machine Identity Security** | Certificate/PKI lifecycle discovery | ✗ | No | Cert lifecycle |
| **Palo Alto PAN-OS PQC Decryption** | Inline TLS ClientHello `supported_groups` inspection (detect/block/log) | ✗ | No (inline network) | Detect + enforce |
| **Palo Alto Quantum-Safe Security** (Jan 2026) | Passive telemetry aggregation (NGFW/Prisma/EDR logs) + Cipher Translation Proxy (live re-encrypt to ML-KEM) | ✗ | No | **Yes** — proxy remediation |
| **Quantum Xchange CipherInsights** | Passive network listener — cert + protocol discovery | **claims CBOM** (format unconfirmed) | No | Discovery |
| PQShield | — (crypto *implementation IP*, not a scanner) | — | — | — |
| Thales CipherTrust DDC | Sensitive-**data** (PII/PHI) discovery — **not** crypto-asset | — | — | — |
| Cisco / Cloudflare | Transport-layer PQC hardening — **not** discovery | — | — | — |

**No verifiable capability detail** (marketing-only / unreachable): Entrust, Wiz,
Qualys, Tenable, Microsoft (Purview/SymCrypt), AppViewX, Utimaco, ISARA,
DigiCert Device Trust Manager.

**Decisive cross-vendor finding:** across *both* commercial passes, only
**SandboxAQ** does binary/runtime analysis and only **IBM** emits standard
CycloneDX CBOM. Every other verified commercial vendor is passive-network or
static/certificate-based, and none was confirmed to emit CycloneDX CBOM.
pqcscan does **binary analysis + CBOM + all discovery surfaces + 19 frameworks**
in open source — a combination no single verified vendor matches.

### FOSS — the four gap categories
- **Binary/firmware constant matchers** — **FindCrypt-Ghidra** (122-constant DB,
  discontinued 2020) and **Yara-Rules `crypto_signatures.yar`** (AES S-box +
  MD5/SHA init-word matching, legacy 2014–16) use *exactly* pqcscan's v0.9.6
  technique but are **classical-only (zero PQC)** and unmaintained. **capa**
  (import/API + some constants, PE/ELF/.NET) and **binwalk** (entropy, not
  constants) round it out — also no PQC. → our `_crypto_constants.py` matches
  the state of the art and adds Keccak/SHA-3 (the one PQC-adjacent signal).
- **Cert/PKI** — **pkilint** (DigiCert, Python) is the standout: **PQC-aware
  since v0.12.6 (Jan 2025)** with FIPS 203/204/205 ASN.1 modules + ML-DSA/
  SLH-DSA/ML-KEM key-usage validation — deeper *profile* validation than our
  `fs.cert.pqc_x509` OID recognition. **zlint** (Go) has no PQC. **IETF-Hackathon/
  pqc-certificates** ships a **PQC/composite cert test-vector corpus** — usable
  as ground-truth to validate our recognition (accuracy). **certstream-server**
  = live CT-log WebSocket (inventory infra, no sig-alg analysis).
- **Passive / JA4** — the key gap: **JA4+** records extension *type* codes
  (`supported_groups 000a`, `key_share 0033`) but **not their contents**, and
  **Zeek base `ssl.log`** logs only the *negotiated* curve, not the ClientHello
  offered groups. So **no FOSS tool passively fingerprints which PQC groups
  (X25519MLKEM768) an endpoint offers.** (JA4 *does* capture `signature_algorithms`
  contents, so PQC sig-algs would show.) → extending `net.sniff.live` to parse
  ClientHello `supported_groups`/`key_share` is genuine whitespace.
- **SBOM/CVE mappers** — **Syft, Trivy, osv-scanner, Dependency-Track** are all
  **crypto-blind** (package-level, no CBOM). Only **cdxgen** (CBOM from JS/TS
  *source* via constant propagation) and **sbom-tools** (CycloneDX 1.6/1.7
  cryptoProperties *grader*, CNSA 2.0 + IR 8547 PASS/FAIL) touch CBOM. pqcscan
  generates a CBOM from *all* surfaces, not just source.

**CISA ACDI taxonomy** (2024) names four discovery types — network, filesystem,
database, software-package — and calls **embedded/binary crypto detection
"unproven / immature."** pqcscan spans all four *and* ships the embedded-binary
detection CISA flagged as hard (`fs.binary.crypto` + v0.9.6 constants).

### Updated remaining coverage candidates (ranked)
- ✅ ~~Passive PQC ClientHello group fingerprinting~~ — already covered; **v0.9.7**
  grades key_share offers above advertisements (the whitespace no FOSS tool fills).
- ✅ ~~Cert PQC recognition accuracy~~ — **v0.9.7** added the 15 missing FIPS 204/205
  pre-hash OIDs (HashML-DSA/HashSLH-DSA, NIST-CSOR-verified) + a 51-OID ground-truth
  recall oracle (the field's first measured PQC-discovery accuracy baseline).
- ✅ ~~Native-vs-OQS OpenSSL version awareness~~ — **v0.9.8**
  (`host.openssl.pqc_provenance`).
- ✅ ~~Cert PQC recognition recall~~ — **v0.9.9** centralized `fs.cert.pqc_x509`
  on `core.alg`, so it recognizes pre-hash + composite + Falcon certs (was only
  pure `.17-.31`); audit confirmed no other probe carries a stale OID table.

**Every high/medium-value research-derived candidate is now shipped.** The two
that remain are deferred with rationale:
1. **Deeper cert PQC *profile* validation** (pkilint-level key-size/key-usage) —
   needs raw-SPKI DER parsing + the IETF pqc-certificates DER vectors; a
   self-contained follow-up, higher effort than the recall fix already shipped.
2. **JA4/JA4X fingerprint emission** — a client-*correlation* fingerprint with
   **no PQC signal** (JA4 records only the extension *type*; we already extract
   the PQC groups directly), and correctness needs the reference spec's vectors.

## Maintained vs dormant
- **Active (2025-era):** PQCA CBOMkit, csnp/cryptoscan, anvilsecure/pqcscan,
  QuantaSeek, open-quantum-secure, IBM Quantum Safe Explorer, Keyfactor stack.
- **Dormant/niche:** LiuYuancheng evaluator (~2022, pre-CNSA-2.0),
  Hacker21-punk/pqscan, cyberjez/PQC-Scanner, wakaken/pqc-scan.
