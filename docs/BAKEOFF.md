**Run:** measured commit `9e8ab72` (pqcscan 0.10.2), runner `0b21960` · `PYTHONPATH=src .venv/bin/python benchmark/bakeoff/run_bakeoff.py --date 20261017` · 2026-10-17 · Linux 7.0.0-38-generic, DO-Premium-Intel x8, docker 29.9.0

# Bake-off: pqcscan against competing FOSS scanners

Every tool scans the same targets from the accuracy corpus. Raw output is kept in `benchmark/bakeoff/results/20261017/raw/`. `benchmark/bakeoff/normalise.py` maps each tool's output to one row schema and the diff compares `(target, surface, algorithm)` with algorithm names folded to a family (`X25519MLKEM768` = `x25519_kyber768`, `RSA-2048` = `RSA`). Method and limits: [`benchmark/bakeoff/README.md`](../benchmark/bakeoff/README.md).

The corpus was written for pqcscan, so it favours pqcscan on file and certificate targets. One extra source set, cryptoscan's own sample files, is added to give the competitor home ground.

## Tools

| Tool | Commit | Version | Surfaces | Technique |
|---|---|---|---|---|
| pqcscan (this repo) | this repo | 0.10.2 | tls, cert, code | in-process probes: TLS handshakes, X.509 and PKCS#12 parsing, tree-sitter and regex source scan |
| anvilsecure/pqcscan | [`fc74c8201e`](https://github.com/anvilsecure/pqcscan/commit/fc74c8201e661de2f78e5cd98d14686164bab30f) | 0.8.0 | tls | advertised key-exchange groups only, no full handshake; TLS and SSH |
| Mehrn0ush/QuantaSeek | [`bb4a06a28c`](https://github.com/Mehrn0ush/QuantaSeek/commit/bb4a06a28c515dee86602dbd6002ca99e0b3312e) | 0.1.0 | tls | rustls handshake, parses ServerHello; verifies the chain against public roots. Built with one `[lib]` edit to `Cargo.toml` because the pinned commit does not compile |
| QuantaSeek, cert checks off | [`bb4a06a28c`](https://github.com/Mehrn0ush/QuantaSeek/commit/bb4a06a28c515dee86602dbd6002ca99e0b3312e) | 0.1.0 | tls | patched rebuild ([patch](../benchmark/bakeoff/quantaseek-noverify.patch)): certificate and signature checks accepted, plus the same `[lib]` edit |
| csnp/cryptoscan | [`22aad8a9a2`](https://github.com/csnp/cryptoscan/commit/22aad8a9a2046f5bbfdd3c89ea6327888f51bee0) | v1.4.1-0.20261016212122-22aad8a9a204 | cert, code | regex over source and config files; does not parse certificate contents |

## Per-target diff

Distinct `(target, surface, algorithm)` keys. *pqcscan-only* and *tool-only* are keys one side reports and the other does not; *both* is the overlap. Each tool is compared on the surfaces it claims. anvil lists accepted key-exchange groups and nothing else, so it is also shown against pqcscan's group rows alone (scoped), which is the fair comparison; the raw counts include every pqcscan finding anvil does not try to make.

| Target | Tool | pqcscan-only | tool-only | both |
|---|---|---:|---:|---:|
| endpoint-tls10-only | anvil | 3 | 0 | 0 |
| endpoint-rsa-kex-only | anvil | 2 | 0 | 0 |
| endpoint-null-cipher | anvil | 2 | 0 | 0 |
| endpoint-tls12-ecdhe | anvil | 2 | 0 | 0 |
| endpoint-mtls-tls12 | anvil | 1 | 0 | 0 |
| endpoint-tls13-x25519 | anvil | 4 | 0 | 1 |
| endpoint-tls13-hybrid-ed25519 | anvil | 3 | 7 | 1 |
| endpoint-tls13-hybrid-mldsa65 | anvil | 4 | 0 | 0 |
| endpoint-tls10-only | QuantaSeek | 3 | 0 | 0 |
| endpoint-rsa-kex-only | QuantaSeek | 2 | 0 | 0 |
| endpoint-null-cipher | QuantaSeek | 2 | 0 | 0 |
| endpoint-tls12-ecdhe | QuantaSeek | 2 | 0 | 0 |
| endpoint-mtls-tls12 | QuantaSeek | 1 | 0 | 0 |
| endpoint-tls13-x25519 | QuantaSeek | 5 | 0 | 0 |
| endpoint-tls13-hybrid-ed25519 | QuantaSeek | 4 | 0 | 0 |
| endpoint-tls13-hybrid-mldsa65 | QuantaSeek | 4 | 0 | 0 |
| endpoint-tls10-only | QuantaSeek (checks off) | 3 | 0 | 0 |
| endpoint-rsa-kex-only | QuantaSeek (checks off) | 2 | 0 | 0 |
| endpoint-null-cipher | QuantaSeek (checks off) | 2 | 0 | 0 |
| endpoint-tls12-ecdhe | QuantaSeek (checks off) | 1 | 2 | 1 |
| endpoint-mtls-tls12 | QuantaSeek (checks off) | 1 | 0 | 0 |
| endpoint-tls13-x25519 | QuantaSeek (checks off) | 0 | 0 | 5 |
| endpoint-tls13-hybrid-ed25519 | QuantaSeek (checks off) | 0 | 0 | 4 |
| endpoint-tls13-hybrid-mldsa65 | QuantaSeek (checks off) | 0 | 0 | 4 |
| certificate files (16 fixtures) | cryptoscan | 14 | 6 | 2 |
| source tree, corpus cases (43 fixtures) | cryptoscan | 12 | 0 | 34 |
| source tree, cryptoscan's own samples (6 files) | cryptoscan | 6 | 18 | 37 |

anvil, scoped to key-exchange groups only (pqcscan side: net.tls.kex_groups and net.tls.pqc_handshake rows):

| Target | pqcscan-only | tool-only | both |
|---|---:|---:|---:|
| endpoint-tls10-only | 0 | 0 | 0 |
| endpoint-rsa-kex-only | 0 | 0 | 0 |
| endpoint-null-cipher | 0 | 0 | 0 |
| endpoint-tls12-ecdhe | 0 | 0 | 0 |
| endpoint-mtls-tls12 | 0 | 0 | 0 |
| endpoint-tls13-x25519 | 0 | 0 | 1 |
| endpoint-tls13-hybrid-ed25519 | 0 | 7 | 1 |
| endpoint-tls13-hybrid-mldsa65 | 1 | 0 | 0 |

Totals per tool and surface (raw counts, and scoped where a tool has a scope):

| Tool | Surface | Comparison | pqcscan-only | tool-only | both |
|---|---|---|---:|---:|---:|
| anvil | tls | raw | 21 | 7 | 2 |
| anvil | tls | scoped: key-exchange groups only | 1 | 7 | 2 |
| QuantaSeek | tls | raw | 23 | 0 | 0 |
| QuantaSeek (checks off) | tls | raw | 9 | 2 | 14 |
| cryptoscan | cert | raw | 14 | 6 | 2 |
| cryptoscan | code | raw | 18 | 18 | 71 |

QuantaSeek completed no handshake on any target, so every pqcscan-only key is by construction.

## What each tool finds that pqcscan misses

### anvilsecure/pqcscan

- **FFDHE2048, FFDHE3072, SECP256R1, SECP384R1, SECP521R1, X25519, X448** (tls; 1 target: tls13-hybrid-ed25519). **fix:** net.tls.kex_groups reports only the group the server prefers. Enumerate every accepted group (one ClientHello per group) so a hybrid server that still accepts classical-only groups shows as a downgrade path.

### Mehrn0ush/QuantaSeek

It reported nothing on any target, so there is nothing to miss. See below.


### QuantaSeek, cert checks off

- **RSA-SHA256** (tls; 1 target: tls12-ecdhe). **scope:** pqcscan keeps the certificate signature hash in evidence (`signature_hash`) and flags the RSA key. No change planned.
- **TLS 1.2** (tls; 1 target: tls12-ecdhe). **scope:** pqcscan records the negotiated TLS 1.2 version only in the cipher-suite finding. Informational; no change planned.

### csnp/cryptoscan

- **X.509 Certificate** (cert; 6 targets: cert-ecdsa-p256-pem/server.crt, cert-ed25519-pem/server.crt, cert-mldsa65/server.pem and 3 more). **scope:** cryptoscan matches the PEM header and says a file is a certificate. pqcscan parses it and reports the key algorithm. No change.
- **Argon2, bcrypt, HKDF, KMAC, PBKDF2** (code; 3 targets: crypto-samples/crypto_samples.go, crypto-samples/macs_and_kdfs.go, crypto-samples/pqc_algorithms.py). **scope:** key-derivation and MAC inventory. Quantum-safe and outside the PQC-risk question; add only for CBOM completeness.
- **Composite-Signature, Hybrid-KEM** (code; 1 target: crypto-samples/hybrid_crypto.js). **alias:** these name the hybrid idiom itself; pqcscan lists the component algorithms (ML-KEM, ML-DSA, X25519) found in the same file.
- **ECC** (code; 1 target: crypto-samples/crypto_samples.go). **fix:** code.ts.go does not detect `ecdsa.GenerateKey(elliptic.P256(), ...)`. Add ECDSA / elliptic-curve keygen to the Go rules and a `go-ec-real` corpus case.
- **LMS, XMSS** (code; 1 target: crypto-samples/pqc_algorithms.py). **fix:** XMSS and LMS are NIST SP 800-208 stateful hash-based signatures, i.e. PQC. Add them to code.crypto_primitives so they classify as pqc-ready.
- **Poly1305** (code; 1 target: crypto-samples/hybrid_crypto.js). **alias:** pqcscan reports ChaCha20 alone; the Poly1305 half is the same primitive.
- **SHA-512** (code; 4 targets: crypto-samples/CryptoSamples.java, crypto-samples/crypto_samples.go, crypto-samples/crypto_samples.py and 1 more). **fix, low priority:** pqcscan lists SHA-256 but not SHA-384 or SHA-512. They are quantum-safe, so only CBOM completeness is at stake.
- **TLS** (code; 1 target: crypto-samples/hybrid_crypto.js). **scope:** a TLS option block is configuration, not an algorithm. pqcscan covers TLS settings through the net.tls.* and fs.conf.* probes.

## What else the run showed

- **pqcscan-only is not all credit.** On the 19 fixtures whose weak token sits only in a comment or string literal, pqcscan's code.crypto_primitives flags 19, cryptoscan flags 12, and the AST probes (code.ts.*) flag 0. **fix:** run the source stripper in code.crypto_primitives as the AST probes do.
- **QuantaSeek, stock, completed no handshake.** It checks the chain against bundled public roots and the server name, has no flag to relax either (`--ignore-mismatch` is parsed and ignored), and the fixtures are private-CA and carry no subjectAltName. The checks-off row is a patched rebuild that accepts them.
- **QuantaSeek dials port 443 only.** The target's port is ignored and its port loop is not used for the real handshake, so the run bridges each fixture to 127.0.0.1:443 inside a private network namespace. The pinned commit also fails to compile until the library crate is named `quanta_seek`.
- **Silence is not a verdict.** QuantaSeek (checks off) fails on the TLS 1.0, RSA-key-exchange, NULL-cipher and mTLS servers. anvil returns an empty result with no error on every server that is not TLS 1.3, and on the ML-DSA-65 hybrid server. Neither says it could not look.
- **cryptoscan on certificates reads text, not keys.** DER and PKCS#12 hits come from names inside the file (`ecdsa`, `ed25519` in the subject), so the cert-tree overlap is partly coincidence.
- **In-process pqcscan equals the CLI.** The runner uses the probes `--target` and `--path` bind, because the CLI has no probe filter and adds a multi-minute host sweep. One real `pqcscan scan` per surface (tls, cert, code) was compared with the in-process keys: identical on all three.
