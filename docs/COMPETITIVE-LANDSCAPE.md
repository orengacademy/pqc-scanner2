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
11 compliance frameworks with CNSA-2.0/IR-8547 deadlines + **per-finding
confidence scoring** (which the research found *no vendor documents formally*)
+ bilingual EN/MS reports.

The one genuine functional peer is the **commercial, closed-source PQ Crypta
Discovery Agent** (offline on-host, multi-surface, CBOM). We match its design
and add SBOM-dependency mapping, compiled-binary scanning, containers, SARIF,
11-framework compliance, confidence, and bilingual reports — all open-source.
The two surfaces PQ Crypta had that we lacked are now closed:

- **Certificate Transparency lookup** (crt.sh) — shipped `net.ct.crtsh`.
- **Compiled-binary crypto** (ELF/PE/Mach-O) — shipped `fs.binary.crypto`.
- **Live cloud KMS** (AWS/Azure CLI) — shipped `host.cloud_kms`.
- **DB-column cert/key material** — shipped `fs.db.crypto`.
- **Network appliances (F5 BIG-IP / Citrix NetScaler)** — shipped
  `fs.conf.f5` + `fs.conf.netscaler`.

Deliberately *not* adopted: **AST code detection** (sonar-cryptography /
Cryptoscope) — native grammars ship platform-specific compiled artifacts that
would break the any-OS self-contained binary; the confidence model down-ranks
the regex false positives instead.

## Maintained vs dormant
- **Active (2025-era):** PQCA CBOMkit, csnp/cryptoscan, anvilsecure/pqcscan,
  QuantaSeek, open-quantum-secure, IBM Quantum Safe Explorer, Keyfactor stack.
- **Dormant/niche:** LiuYuancheng evaluator (~2022, pre-CNSA-2.0),
  Hacker21-punk/pqscan, cyberjez/PQC-Scanner, wakaken/pqc-scan.
