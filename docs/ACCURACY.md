Measured on commit `9ad4f61` (probe code; `src/` is unchanged in the commit that updates this page) with `PYTHONPATH=src python benchmark/run_benchmark.py --by-family --accept-fp-file benchmark/corpus/accepted_fp.txt`; corpus sha256 `563e427b9eec600c94b9c234b2c514ceba02bdc26d38707431a5aae02b068e0c` (sha256 of `benchmark/corpus/CORPUS.sha256`).

# Detection accuracy

pqcscan's probes are scored against a labelled corpus of 176 cases: 96 positives, where the probe should fire, and 80 negatives, where it should stay silent. The cases cover certificates, keys, keystores, local TLS endpoints, source snippets, config files, SQLite files and two OCI container images. A probe "fires" when it emits a finding in a weak or quantum-vulnerable tier (`sangat-tinggi`, `tinggi`, `sederhana`, `rendah`). INFO, ERROR and `pqc-ready` findings never count. A positive with an `expect` block counts only when the matching finding fires. See `benchmark/README.md` for the scoring rule.

Overall: **precision 1.000, recall 0.990** (TP 95, FP 0, FN 1, TN 72, plus 8 accepted false positives; raw precision with those counted is 0.922; no cases skipped or errored on this host). The 8 accepted false positives are a deliberate fail-open choice in `code.crypto_primitives` (see Limits). They are listed in `benchmark/corpus/accepted_fp.txt`, which the harness (`--accept-fp-file`, as CI runs it) and the pytest gate both read. They are reported as AFP rows and left out of precision. The run fails on any other false positive, or if a listed case stops firing. A case whose probe or fixture raises is recorded as ERROR, kept out of the counts and fails the run, so a crash can never pass as a plain FN.

## Per family

A family is the probe id up to the second dot.

| family | probes | TP | FP | FN | TN | precision | recall |
|---|---|---:|---:|---:|---:|---:|---:|
| code.crypto_primitives | crypto_primitives (17 suffixes) | 22 | 0 (+8 accepted) | 0 | 22 | 1.000 (raw 0.733) | 1.000 |
| code.ts | csharp, go, java (incl. Kotlin), javascript, php, python, rust | 20 | 0 | 0 | 27 | 1.000 | 1.000 |
| fs.binary | crypto | 1 | 0 | 0 | 1 | 1.000 | 1.000 |
| fs.cert | x509, privkey, privkey_encrypted | 15 | 0 | 0 | 4 | 1.000 | 1.000 |
| fs.conf | f5, haproxy, netscaler, nginx, openssl_cnf, sshd | 7 | 0 | 0 | 6 | 1.000 | 1.000 |
| fs.db | crypto | 1 | 0 | 0 | 1 | 1.000 | 1.000 |
| fs.keystore | pkcs12 | 6 | 0 | 0 | 1 | 1.000 | 1.000 |
| fs.ssh | host_keys | 4 | 0 | 0 | 1 | 1.000 | 1.000 |
| net.tls | versions, kex_groups, https, cert_chain, cert_chain_tls13, pqc_handshake | 18 | 0 | 1 | 8 | 1.000 | 0.947 |
| sbom.crypto_map | crypto_map | 1 | 0 | 0 | 1 | 1.000 | 1.000 |
| **overall** | 28 probes | **95** | **0 (+8 accepted)** | **1** | **72** | **1.000 (raw 0.922)** | **0.990** |

## Probes below 1.0

| probe | TP | FP | FN | TN | precision | recall | miss |
|---|---:|---:|---:|---:|---:|---:|---|
| code.crypto_primitives | 22 | 0 (+8 accepted) | 0 | 22 | 1.000 (raw 0.733) | 1.000 | comment and prose-string mentions in C, C++, Ruby and Swift fire by design (fail-open, see Limits) |
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

## Bake-off fixes

The scanner bake-off (`docs/BAKEOFF.md`) found two gaps. `code.crypto_primitives` was not in the corpus at all, so the precision of 1.0 above did not cover it.

| commit | problem | corpus cases | before | now |
|---|---|---|---|---|
| `4df285e` | `code.crypto_primitives` matched raw text, so an algorithm name in a comment or a prose string fired on every language it scans. Matches now go through the comment/string lexer: comments never count, and a string counts only when it is a bare identifier such as `"MD5"` or `"AES/GCM/NoPadding"`. The probe anchors on the algorithm token itself, so masking strings outright would lose `getInstance("MD5")`. The lexer gains C/C++, Python and Ruby; Swift uses the Java rules and TypeScript the JavaScript rules. | 13 positives (real MD5 use, one per scanned suffix) and 30 negatives (comment-only and prose-string-only, every suffix, including the text-block and raw-string cases) | P 0.302 (30 FP) | P 1.000, R 1.000 |
| `23646a5` | Follow-up to `d0d97ce`: each comment/string span is decided once, and a span over 64 kB counts as code without inspection (fail open). Re-inspecting the span for every match inside it was quadratic. A 1 MiB literal with 10,000 `md5(` tokens now scans as fast as a token-free 1 MiB file. | (unit tests; corpus results unchanged) | — | — |
| `d0d97ce` | Security review, round 2: five crafted literals hid MD5 from `7469e2a`. Each is a construct the lexer misreads: a JS/TS regex `/"/`, a Python 3.12 nested f-string quote, a C# 11 raw string, a Kotlin nested template. Each leaves a stray quote whose "string" swallows the next statement. Such a string span now counts as code when it holds one of the probe's own primitives in call context (derived from its pattern table) and code punctuation (`; = + , | & ?`). A call token alone would also have flagged 9 of the 30 prose negatives, such as `"md5($password) is forbidden"`. Also: a bare `"LMS"` passed to a crypto call is recognised, and `.cc`/`.cxx`/`.h`/`.hpp` are scanned unstripped. | 5 positives: `cp-js-regex-quote-md5`, `cp-ts-regex-quote-md5`, `cp-py312-fstring-quote-md5`, `cp-cs-rawstring-quote-md5`, `cp-kt-template-quote-md5`. All 5 are FN on `7469e2a` and TP now. | — | P 1.000, raw 0.733 |
| `7469e2a` | Security review of `4df285e`, which ruled that a false positive is cheaper than a hidden MD5. C/C++, Ruby and Swift are no longer lexed, because raw strings, regex and `%`-literals, `?x` characters and heredocs could make a crafted literal blank real code. A string that can interpolate code (`${…}`, `{$…}`, `#{…}`, Python f-strings, C# `$"…"`) counts as code. | 4 positives: `cp-js-template-md5`, `cp-py-fstring-md5`, `cp-rb-charliteral-then-md5` (`?"` followed by a real call), `cp-swift-rawstring-then-md5` (`#"a"b"#` followed by a real call). All 4 are FN on `d9e3b84` and TP now. | — | P 0.680 by design: the 8 C/C++/Ruby/Swift comment/string negatives fire |
| `d9e3b84` | XMSS, XMSS^MT, LMS and HSS/LMS (SP 800-208) were not recognised by their X.509 OIDs or as `HSS/LMS` names, and `code.crypto_primitives` did not see them in source. | none: `pqc-ready` never counts as a fire, so unit tests cover it | — | — |

## Security-review fixes

A security review of the fixes above found three more problems. Each was fixed in its own commit with unit tests and a CHANGELOG entry. Each also got corpus cases, and every new positive scores FN on the pre-review code (`10f789c`) and TP now.

| commit | problem | corpus cases |
|---|---|---|
| `a8a23a0` | The `5db4f0a` text-block rule closed on an escaped `\"""` and on the first quote of a closing run. A crafted string could make the stripper blank a real `MessageDigest.getInstance("MD5")` after it, which is a scanner evasion. Java text blocks now honour escapes, need a line break after the opening `"""` and close on the final quote run. Kotlin and Scala raw strings have their own rule with no escapes. | `java-textblock-evasion`, `kt-rawstring-evasion` (positive); `java-textblock-md5-string`, `kt-rawstring-trailing-quote-md5` (negative) |
| `3e5a785` | Follow-up to `a8a23a0`: the lazy text-block body was ambiguous, because a quote matched two alternatives. Both triple-quoted rules now use a disjoint possessive body, so the body cannot backtrack. Inputs over 2 MiB are scanned unstripped with an INFO note. That did not make stripping linear; see `e78c763`. | (unit tests; corpus results unchanged) |
| `e78c763` | An unterminated `"`/`'` was rescanned from every later quote on its line, which is quadratic: about 10 s for one 40 k-character line. Rust raw-string floods were also quadratic. Every form that can fail now has a non-blanking partner that consumes what it rejected, so stripping is linear: quotes to the end of the line; block comments and verbatim strings once to the end of input, after which the scan resumes without that form. Timing tests cover every language with 1 MiB single-line inputs. | (unit tests; corpus results unchanged) |
| `45c03cc` | Follow-up to `e78c763`. Dropping the Rust raw-string form after one unterminated `r##"` let a later `r"\"` be read as an ordinary string, which blanked the real call after it: an evasion. Raw closers are now found by hash count from a one-pass index, so each opener is decided in O(1). Unterminated Java text blocks and Kotlin raw strings got end-of-input partners, because openers inside a failed body rescanned to the end: 17 s for 64 KiB. | (unit tests; corpus results unchanged) |
| `2fc607a` | CI on real OpenSSL 3.0.13 missed `ep-tls13-x25519-pqc-handshake`: `s_client` rejected the hybrid group name, so the probe classified nothing. It now falls back to the raw ClientHello of `net.tls.kex_groups`. Re-asking `s_client` with classical groups only would make hybrid-capable servers look like classical fallbacks, so that was not done. | (loopback unit tests with `s_client` stubbed to fail as on 3.0; corpus results on this host unchanged) |
| `adee2ff` | Minor: one shared signature-scheme list for the raw TLS probes, and negotiated-suite findings record the client mode (`evidence.client`). | (unit tests; corpus results unchanged) |
| `15823df` | `fs.keystore.pkcs12` raised on a CA cert with an unknown key type, which ended the walk. One crafted `.p12` hid every other keystore. Each cert and each file is now guarded and reported as an INFO `UNKNOWN` finding. | `p12-weak-plus-garbage-ca`, `p12-garbage-ca-sibling-scanned` (positive) |
| `9a43eff` | The OpenSSL-name branch of `classify_suite` rated anonymous, export, DES/3DES and CBC-with-SHA-1 suites (`AES128-SHA`, `ECDHE-RSA-AES128-SHA`) as `tinggi` or `info`, below their RFC spelling. OpenSSL names now get the RFC grade, pinned by a parity test. | `ep-cbc-sha1-https` (positive, must be `sangat-tinggi`) |

## Limits

- **Hybrid-KEM negatives need OpenSSL 3.5 or newer.** Python's `ssl` cannot pick groups: `set_ecdh_curve` takes one classical group. OpenSSL 3.5 offers `X25519MLKEM768` first by default, and the Python here links OpenSSL 3.5.7, so the hybrid endpoints are real. They carry `requires_openssl: [3, 5]` and are recorded as SKIP on older builds, such as a system Python on Ubuntu 24.04 with OpenSSL 3.0. The CI accuracy job on `ubuntu-latest` uses the real OpenSSL 3.0.13 ([run 39036012109](https://github.com/orengacademy/pqc-scanner2/actions/runs/39036012109)). It measured precision 1.000 and **recall 0.973**: 71 of 73 scored positives, with those 8 cases skipped. That run missed `ep-tls13-x25519-pqc-handshake` as well as `ep-mtls-https`. `net.tls.pqc_handshake` could only report that the local openssl does not support hybrid groups, because OpenSSL 3.0's `s_client` rejects the `X25519MLKEM768` name. `2fc607a` fixes that: the probe now asks the server through the raw ClientHello of `net.tls.kex_groups`, which offers the hybrid groups without local support. Loopback unit tests stub `s_client` to fail as it does on 3.0, and the X25519-only server is flagged. CI then measured recall 0.986 (72 of 73) on that 124-case corpus ([run 39037117645](https://github.com/orengacademy/pqc-scanner2/actions/runs/39037117645)) and 0.988 (85 of 86) on a 167-case corpus (run 39037633212). On the current 176-case corpus the expected CI figure is 94/95 = 0.989: of the 8 skipped hybrid-KEM cases, 7 are negatives and `ep-hybrid-ed25519-cert-chain` is a positive, which leaves 95 positives on OpenSSL 3.0 with `ep-mtls-https` missed. The 0.990 above (95/96) is the local OpenSSL 3.5.7 run. Neither is measured in CI yet. An earlier simulated OpenSSL 3.0 run that forced only the version check gave 0.985; it did not exercise the 3.0 `s_client`, which is why it missed this.
- **No RC4 or 3DES servers.** OpenSSL 3.x builds do not ship those TLS suites, so `NULL-SHA256` stands in as the weak-cipher endpoint.
- **No live daemon probes.** `container.image.sbom`, `container.runtime.detect` and `sbom.syft` need docker, podman or syft and emit only INFO findings, so they are not scored. pqcscan has no native OCI image reader.
- **Image fixtures are a flattened rootfs.** The harness applies the layers of a single-layer OCI layout and points the file probes at the result, which emulates `docker export` followed by `pqcscan scan --path`. Whiteouts are not handled. The bundled `libssl` is ELF magic plus an OpenSSL version banner, so the `DT_NEEDED` linkage path of `fs.binary.crypto` is not exercised.
- **`net.tls.https` has no negative case.** Every TLS 1.3 suite classifies as `rendah` or `sederhana`, which the scoring rule counts as a detection, so even a fully post-quantum endpoint fires. Its precision is therefore untested by a negative.
- **TLS probes are paired by protocol.** `net.tls.cert_chain` reads the TLS 1.2 Certificate message and is paired only with TLS 1.0–1.2 endpoints. `net.tls.kex_groups`, `net.tls.cert_chain_tls13` and `net.tls.pqc_handshake` are paired only with TLS 1.3 endpoints.
- **No encrypted post-quantum negatives.** A PKCS#12 or encrypted PKCS#8 file whose password the probe does not know is flagged from its container format alone (`PKCS12-ENCRYPTED`, `PKCS8-PBES2`). The probe cannot see what is inside, so a "negative" label would be untestable. `cryptography` also cannot put an ML-DSA key in a PKCS#12 file.
- **OpenSSH coverage is public keys only.** `fs.ssh.host_keys` reads `*.pub` and `authorized_keys`. No probe reads OpenSSH-format private keys. Encrypted OpenSSH keys need the `bcrypt` package, which is not a dependency.
- **`code.crypto_primitives` fails open for C, C++, Ruby and Swift.** No lexer is trusted for them, and a wrong one would let a crafted literal hide real code. So those files are scanned unstripped, and a comment or prose-string mention there fires. These are the corpus's 8 false positives, listed in `benchmark/corpus/accepted_fp.txt`, which the harness and the pytest gate both read. In the stripped languages, a literal that can interpolate code counts as code.
- **Known misses, not fixed:**
  - **Single DES.** `code.crypto_primitives` has patterns for 3DES (`3DES`, `DESede`, `TripleDES`) but not single DES (`DES/ECB`, `DES.new`, `DESCryptoServiceProvider`). Single-DES use in a language without a `code.ts.*` probe goes unreported.
  - **PHP 8 attributes.** The PHP lexer treats `#` as a line comment, so an attribute line `#[...]` is blanked to the end of the line. Code after an attribute on the same line, such as `#[Pure] function h($x) { return md5($x); }`, is hidden from `code.ts.php` and `code.crypto_primitives`.
- **Kotlin has no probe of its own.** `.kt` files are scanned by `code.ts.java`.
- **Scoring is per case, not per finding.** A wrong extra finding next to a correct one is invisible to the score. The false "accepts TLS 1.1" report was found by inspecting findings, not by the numbers.
- **The corpus is small and synthetic.** Each probe has a handful of cases, so one miss moves a score by 0.1 to 0.3.

## Reproduce

```bash
PYTHONPATH=src python benchmark/corpus/generate_fixtures.py         # regenerate fixtures + CORPUS.sha256 (~30 s)
PYTHONPATH=src python benchmark/run_benchmark.py --by-family --accept-fp-file benchmark/corpus/accepted_fp.txt --min-precision 1.0 --min-recall 0.95   # this table + the CI gate (~6 s; TLS servers on 127.0.0.1)
PYTHONPATH=src python -m pytest -q tests/benchmark/test_accuracy.py  # gate: no FP outside accepted_fp.txt (none stale), recall >= 0.95, hashes and doc current
```

Keys come from fixed seeds, and serials and dates are fixed. ECDSA signs per RFC 6979, and tar and JSON output is canonical, so regeneration reproduces the same bytes. Some formats are always salted or signed with randomness: ML-DSA certificates, PKCS#12, encrypted PKCS#8 and PEM, and OpenSSH private keys. Those are written once and kept, and `CORPUS.sha256` pins their bytes. TLS servers bind to free ports on 127.0.0.1, and no traffic leaves loopback.
