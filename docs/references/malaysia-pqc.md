# Malaysia PQC References

Authoritative Malaysian sources for the PQC compliance framework engine.

## Sources

### 1. CyberSecurity Malaysia (CSM / MyKripto) — Migration Framework
- **URL:** https://mykripto.cybersecurity.my/index.php/files/109/Post-Quantum/18/Post-quantum-Cryptography-Migration-Framework.pdf
- **Use:** Canonical reference for the PQC migration framework; informs the BUKUKERJA workbook structure and risk classifications. To be encoded as `frameworks/mykripto-migration-framework.yaml` in Plan C.

### 2. NACSA Arahan KE No. 9
- **URL:** https://www.nacsa.gov.my/doc/Arahan%20KE%20NACSA%20No.%209.pdf
- **Issuer:** Agensi Keselamatan Siber Negara (NACSA, the National Cyber Security Agency).
- **Use:** Government-mandated cyber-security directive that includes PQC migration requirements. To be encoded as `frameworks/nacsa-arahan-ke-9.yaml` in Plan C with verdict mappings (compliant / non-compliant / advisory) and any deadlines stated in the directive.

### 3. CyberSecurity Malaysia — Post-Quantum Overview
- **URL:** https://www.cybersecurity.my/portal-main/services/post-quantum-overview
- **Use:** Programmatic context for CSM's PQC stance; cited from README and the design spec.

### 4. MyKripto — PQC Initiatives Document Index
- **URL:** https://mykripto.cybersecurity.my/index.php/services/post-quantum-cryptography-initiatives/documents
- **Use:** Index page; consult for follow-up documents (workshop materials, technical guides, the BUKUKERJA template itself).

## How these feed the implementation

| Source | Plan A (this MVP) | Plan C (compliance engine) | Plan D (renderers) |
|---|---|---|---|
| MyKripto Migration Framework | Cited in design spec; algorithm classifications already align (Sangat Tinggi / Tinggi / Sederhana / Rendah / PQC-Ready) | New `frameworks/mykripto-migration-framework.yaml` | XLSX renderer aligns with framework headings |
| NACSA Arahan KE No. 9 | Mentioned here; defers binding behaviour to Plan C | New `frameworks/nacsa-arahan-ke-9.yaml` (with deadline fields) | PDF executive summary cites the directive number |
| CSM PQC Overview | README/spec reference link | n/a | n/a |
| MyKripto Initiatives index | n/a | Source-of-truth crawl seed for new framework YAMLs as they're published | n/a |

## Glossary (Malay → English)

- **Sangat Tinggi** — Very High (risk)
- **Tinggi** — High (risk)
- **Sederhana** — Medium (risk)
- **Rendah** — Low (risk)
- **PQC-Ready** — Post-Quantum Cryptography compliant
- **BUKUKERJA** — Workbook (refers to BUKUKERJA BENGKEL MIGRASI PQC 2025 — "Workshop Workbook on PQC Migration 2025")
- **NACSA** — Agensi Keselamatan Siber Negara (National Cyber Security Agency)
- **MyKripto** — CyberSecurity Malaysia's cryptography portal
- **Arahan KE** — Executive Directive
