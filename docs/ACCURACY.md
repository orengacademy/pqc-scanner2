Measured on commit `9a43eff` (probe code; `src/` is unchanged in the commit that updates this page) with `PYTHONPATH=src python benchmark/run_benchmark.py --by-family`; corpus sha256 `f37b8344c0428c80c2eabeb62cc2d9417460392869275272621b0e9769a94c3c` (sha256 of `benchmark/corpus/CORPUS.sha256`).

# Detection accuracy

pqcscan's probes are scored against a labelled corpus of 124 cases: 74 positives, where the probe should fire, and 50 negatives, where it should stay silent. The cases cover certificates, keys, keystores, local TLS endpoints, source snippets, config files, SQLite files and two OCI container images. A probe "fires" when it emits a finding in a weak or quantum-vulnerable tier (`sangat-tinggi`, `tinggi`, `sederhana`, `rendah`). INFO, ERROR and `pqc-ready` findings never count. A positive with an `expect` block counts only when the matching finding fires. See `benchmark/README.md` for the scoring rule.

Overall: **precision 1.000, recall 0.986** (TP 73, FP 0, FN 1, TN 50, no cases skipped on this host).

## Per family

A family is the probe id up to the second dot.

| family | probes | TP | FP | FN | TN | precision | recall |
|---|---|---:|---:|---:|---:|---:|---:|
| code.ts | csharp, go, java (incl. Kotlin), javascript, php, python, rust | 20 | 0 | 0 | 27 | 1.000 | 1.000 |
| fs.binary | crypto | 1 | 0 | 0 | 1 | 1.000 | 1.000 |
| fs.cert | x509, privkey, privkey_encrypted | 15 | 0 | 0 | 4 | 1.000 | 1.000 |
| fs.conf | f5, haproxy, netscaler, nginx, openssl_cnf, sshd | 7 | 0 | 0 | 6 | 1.000 | 1.000 |
| fs.db | crypto | 1 | 0 | 0 | 1 | 1.000 | 1.000 |
| fs.keystore | pkcs12 | 6 | 0 | 0 | 1 | 1.000 | 1.000 |
| fs.ssh | host_keys | 4 | 0 | 0 | 1 | 1.000 | 1.000 |
| net.tls | versions, kex_groups, https, cert_chain, cert_chain_tls13, pqc_handshake | 18 | 0 | 1 | 8 | 1.000 | 0.947 |
| sbom.crypto_map | crypto_map | 1 | 0 | 0 | 1 | 1.000 | 1.000 |
| **overall** | 27 probes | **73** | **0** | **1** | **50** | **1.000** | **0.986** |

## Probes below 1.0

| probe | TP | FP | FN | TN | precision | recall | miss |
|---|---:|---:|---:|---:|---:|---:|---|
| net.tls.https | 6 | 0 | 1 | 0 | 1.000 | 0.857 | `ep-mtls-https`: the endpoint requires a client certificate |

Every other probe scores 1.000 on both measures. Full per-probe and per-case numbers are in `benchmark/last_report.json`.

## Probes under 0.9

Five probes scored under 0.9 on the first run of the extended corpus, with overall precision 0.955 and recall 0.913. Each was fixed in `src/` with a unit test and a CHANGELOG entry, except one residual miss explained below.

| probe | first run | cause | fix | now |
|---|---|---|---|---|
| code.ts.java | P 0.800 | The comment/string stripper had no rule for `"""..."""`, so a call quoted in a Kotlin raw string or a Java text block was scanned as code. | `5db4f0a` | P 1.000 |
| fs.keystore.pkcs12 | R 0.750 | The CA list from a PKCS#12 file was discarded, so a cert-only truststore of RSA CAs gave no finding. | `6d7f0c6`, `601f378` | R 1.000 |
| net.tls.versions | P 0.667 | The ClientHello offered no Ed25519 or ML-DSA signature scheme. Servers with such a certificate aborted, and the probe reported "no TLS 1.3" on both hybrid-PQC endpoints. It also took any ServerHello as acceptance, so a TLS-1.0-only server "accepted" TLS 1.1. | `b31dc24` | P 1.000 |
| net.tls.pqc_handshake | R 0.000 | The `-groups` list named `X25519Kyber768Draft00`, which OpenSSL 3.5 rejects, so `s_client` never connected. OpenSSL 3.2+ also prints `Peer Temp Key:`, which the parser did not read. | `593649a` | R 1.000 |
| net.tls.https | R 0.333 | The stock client context refused TLS 1.0, static-RSA and NULL servers. `classify()` also rated OpenSSL suite names such as `AES256-GCM-SHA384` and `NULL-SHA256` as info. | `2e3b85d` | R 0.857 |

The same `b31dc24` fix also applies to `net.tls.kex_groups` and `net.tls.cert_chain_tls13`. Before it, both scored their hybrid negatives as TN only because the handshake failed. They now report `X25519MLKEM768` and the ML-DSA-65 leaf as `pqc-ready`.

**Residual `net.tls.https` miss, not fixed.** The mTLS endpoint requires a client certificate. Python's `ssl` client cannot finish that handshake, so it never exposes the server certificate. Recovering it would mean parsing the handshake by hand, which `net.tls.cert_chain` already does, and that probe detects the endpoint's RSA-2048 certificate (`ep-mtls-cert-chain` is a TP). For mTLS endpoints, rely on `net.tls.cert_chain`.

## Security-review fixes

A security review of the fixes above found three more problems. Each was fixed in its own commit with unit tests and a CHANGELOG entry. Each also got corpus cases, and every new positive scores FN on the pre-review code (`10f789c`) and TP now.

| commit | problem | corpus cases |
|---|---|---|
| `a8a23a0` | The `5db4f0a` text-block rule closed on an escaped `\"""` and on the first quote of a closing run. A crafted string could make the stripper blank a real `MessageDigest.getInstance("MD5")` after it, which is a scanner evasion. Java text blocks now honour escapes, need a line break after the opening `"""` and close on the final quote run. Kotlin and Scala raw strings have their own rule with no escapes. | `java-textblock-evasion`, `kt-rawstring-evasion` (positive); `java-textblock-md5-string`, `kt-rawstring-trailing-quote-md5` (negative) |
| `15823df` | `fs.keystore.pkcs12` raised on a CA cert with an unknown key type, which ended the walk. One crafted `.p12` hid every other keystore. Each cert and each file is now guarded and reported as an INFO `UNKNOWN` finding. | `p12-weak-plus-garbage-ca`, `p12-garbage-ca-sibling-scanned` (positive) |
| `9a43eff` | The OpenSSL-name branch of `classify_suite` rated anonymous, export, DES/3DES and CBC-with-SHA-1 suites (`AES128-SHA`, `ECDHE-RSA-AES128-SHA`) as `tinggi` or `info`, below their RFC spelling. OpenSSL names now get the RFC grade, pinned by a parity test. | `ep-cbc-sha1-https` (positive, must be `sangat-tinggi`) |

## Limits

- **Hybrid-KEM negatives need OpenSSL 3.5 or newer.** Python's `ssl` cannot pick groups: `set_ecdh_curve` takes one classical group. OpenSSL 3.5 offers `X25519MLKEM768` first by default, and the Python here links OpenSSL 3.5.7, so the hybrid endpoints are real. They carry `requires_openssl: [3, 5]` and are recorded as SKIP on older builds, such as a system Python on Ubuntu 24.04 with OpenSSL 3.0. A simulated OpenSSL 3.0 run skips 8 cases and still scores precision 1.000 and recall 0.985. That simulation forces only the version check; the other endpoints were not run against a real OpenSSL 3.0.
- **No RC4 or 3DES servers.** OpenSSL 3.x builds do not ship those TLS suites, so `NULL-SHA256` stands in as the weak-cipher endpoint.
- **No live daemon probes.** `container.image.sbom`, `container.runtime.detect` and `sbom.syft` need docker, podman or syft and emit only INFO findings, so they are not scored. pqcscan has no native OCI image reader.
- **Image fixtures are a flattened rootfs.** The harness applies the layers of a single-layer OCI layout and points the file probes at the result, which emulates `docker export` followed by `pqcscan scan --path`. Whiteouts are not handled. The bundled `libssl` is ELF magic plus an OpenSSL version banner, so the `DT_NEEDED` linkage path of `fs.binary.crypto` is not exercised.
- **`net.tls.https` has no negative case.** Every TLS 1.3 suite classifies as `rendah` or `sederhana`, which the scoring rule counts as a detection, so even a fully post-quantum endpoint fires. Its precision is therefore untested by a negative.
- **TLS probes are paired by protocol.** `net.tls.cert_chain` reads the TLS 1.2 Certificate message and is paired only with TLS 1.0–1.2 endpoints. `net.tls.kex_groups`, `net.tls.cert_chain_tls13` and `net.tls.pqc_handshake` are paired only with TLS 1.3 endpoints.
- **No encrypted post-quantum negatives.** A PKCS#12 or encrypted PKCS#8 file whose password the probe does not know is flagged from its container format alone (`PKCS12-ENCRYPTED`, `PKCS8-PBES2`). The probe cannot see what is inside, so a "negative" label would be untestable. `cryptography` also cannot put an ML-DSA key in a PKCS#12 file.
- **OpenSSH coverage is public keys only.** `fs.ssh.host_keys` reads `*.pub` and `authorized_keys`. No probe reads OpenSSH-format private keys. Encrypted OpenSSH keys need the `bcrypt` package, which is not a dependency.
- **Kotlin has no probe of its own.** `.kt` files are scanned by `code.ts.java`.
- **Scoring is per case, not per finding.** A wrong extra finding next to a correct one is invisible to the score. The false "accepts TLS 1.1" report was found by inspecting findings, not by the numbers.
- **The corpus is small and synthetic.** Each probe has a handful of cases, so one miss moves a score by 0.1 to 0.3.

## Reproduce

```bash
PYTHONPATH=src python benchmark/corpus/generate_fixtures.py         # regenerate fixtures + CORPUS.sha256 (~30 s)
PYTHONPATH=src python benchmark/run_benchmark.py --by-family         # this table (~6 s; TLS servers on 127.0.0.1)
PYTHONPATH=src python -m pytest -q tests/benchmark/test_accuracy.py  # gate: precision == 1.0, recall >= 0.95
```

Keys come from fixed seeds, and serials and dates are fixed. ECDSA signs per RFC 6979, and tar and JSON output is canonical, so regeneration reproduces the same bytes. Some formats are always salted or signed with randomness: ML-DSA certificates, PKCS#12, encrypted PKCS#8 and PEM, and OpenSSH private keys. Those are written once and kept, and `CORPUS.sha256` pins their bytes. TLS servers bind to free ports on 127.0.0.1, and no traffic leaves loopback.
