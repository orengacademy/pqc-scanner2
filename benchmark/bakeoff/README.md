# Bake-off: pqcscan against competing scanners

Runs pqcscan and three other open-source scanners over the same targets, normalises every tool's output to one
row schema, and writes a finding-level diff. The write-up is [`docs/BAKEOFF.md`](../../docs/BAKEOFF.md); the data is
`results/<date>/bakeoff.json` and the untouched tool output is `results/<date>/raw/`.

```bash
# scan, normalise, diff, write docs/BAKEOFF.md. --build builds any missing tool image first (Rust and Go compile in
# containers: about 10 minutes the first time). The run itself takes about 5 minutes, mostly the real-CLI cross-check.
PYTHONPATH=src .venv/bin/python benchmark/bakeoff/run_bakeoff.py --build --date 20261017

# after editing normalise.py or report.py: rebuild rows, diffs and the doc from the saved raw files, no rescan
PYTHONPATH=src .venv/bin/python benchmark/bakeoff/run_bakeoff.py --from-raw --date 20261017
```

`--tools a,b` limits the run; `--no-cli-crosscheck` skips the slow comparison against the real `pqcscan scan` CLI.

## Tools and pins

| Tool | Language | Pinned commit | Image |
|---|---|---|---|
| [anvilsecure/pqcscan](https://github.com/anvilsecure/pqcscan) 0.8.0 | Rust | `fc74c8201e661de2f78e5cd98d14686164bab30f` | `Dockerfile.anvil`, built `--locked` |
| [Mehrn0ush/QuantaSeek](https://github.com/Mehrn0ush/QuantaSeek) 0.1.0 | Rust | `bb4a06a28c515dee86602dbd6002ca99e0b3312e` | `Dockerfile.quantaseek`, targets `stock` and `noverify` |
| [csnp/cryptoscan](https://github.com/csnp/cryptoscan) v1.4.1 | Go | `22aad8a9a2046f5bbfdd3c89ea6327888f51bee0` | `Dockerfile.cryptoscan` |

The commit in each Dockerfile (`ARG COMMIT`) is the only place a tool pin lives; `run_bakeoff.py` and `docs/BAKEOFF.md`
read it from there. Base images are pinned by digest and `socat` by package version. QuantaSeek's repo ships no
`Cargo.lock`, so its dependency versions float within `Cargo.toml` ranges; the lock the build resolved is saved at
`results/<date>/quantaseek-Cargo.lock` (a rebuild later may resolve newer crates). There is no cargo or Java on the host, so Rust and Go build in containers.

Not run:

- **CBOMkit and sonar-cryptography** (PQCA). The CBOMkit service needs a Postgres backend and takes a git URL, no
  published image could be pulled anonymously, and sonar-cryptography is a SonarQube plugin that needs a Java build
  of the scanned code. Neither runs offline against a directory in under ten minutes of setup.
- **anvil's SSH scan and `pqcdump`**. The corpus has no SSH server or capture to point them at.

## Targets

All come from the accuracy corpus (`benchmark/corpus/cases`) and are listed by name in `run_bakeoff.py`, so the
bake-off does not move when the corpus grows. They are the cases committed at `10f789c`.

| Set | What | Started by |
|---|---|---|
| tls | 8 local TLS servers: TLS 1.0 only, RSA key exchange, NULL cipher, TLS 1.2 ECDHE, mTLS, TLS 1.3 X25519, two TLS 1.3 hybrid (Ed25519 and ML-DSA-65 certificates) | `run_benchmark.tls_endpoint`, the harness helper, for every tool |
| cert | 16 fixtures: RSA, ECDSA, Ed25519, ML-DSA-65 certificates in PEM and DER, and five PKCS#12 stores | copied side by side into one directory |
| code | 43 fixtures in 8 languages (real weak call, same token in a comment, in a string, clean SHA-256), plus cryptoscan's own `crypto-samples/` (6 files) | copied into one tree |

`endpoint-cbc-sha1` and the stripper-evasion cases (`java-textblock-*`, `kt-rawstring-*`) were added to the corpus after
`10f789c`, so they are not targets; adding one means a rescan and a new dated result.

The accuracy corpus was written against pqcscan's probes, so the cert and code sets favour pqcscan. The
`crypto-samples/` files come out of the cryptoscan image (pinned commit) to give that tool home ground.

## How each tool is run

- **pqcscan** runs in-process: the same probes `--target host:port` (the six `net.tls.*` probes that take a host) and
  `--path dir` (`fs.cert.x509`, `fs.cert.pqc_x509`, `fs.keystore.*`, every `code.*` probe) bind, through the runner's
  own `bind_context`. The CLI has no probe filter and adds a host sweep of several minutes per call, which is too slow
  for nine targets. Instead the run executes one real `python -m pqcscan scan` per surface, reads the findings back
  from its SQLite database and checks the `(target, surface, algorithm)` keys equal the in-process ones. The result is
  in `bakeoff.json` under `meta.cli_crosscheck`.
- **anvil** `tls-scan --test-nonpqc-algos -t 127.0.0.1:<port>`. Without that flag a classical server reports nothing.
- **QuantaSeek** `quantaseek -q --tls12 --ignore-mismatch 127.0.0.1`, twice: the stock binary, and a build with
  certificate and signature checks accepted (`quantaseek-noverify.patch`). Three upstream facts drive this:
  1. The pinned commit does not compile: the package is `QuantaSeek` but `main.rs` imports `quanta_seek`. The
     Dockerfile adds `[lib] name = "quanta_seek"` to `Cargo.toml`; no source file changes in the stock build.
  2. It always verifies the chain against bundled public roots and the server name (`--ignore-mismatch` is parsed and
     dropped). The fixtures are private-CA and have no subjectAltName, so the stock binary completes no handshake.
     The patch (about 60 lines in `handshake.rs`) accepts any certificate and signature; it changes nothing else.
  3. It ignores the port in the target and dials `<target>:443`. Port 443 is in use on the bake-off host, so each
     endpoint is bridged to 127.0.0.1:443 inside a private network namespace: a host-side unix-socket relay
     (`UnixRelay`) plus a `socat` sidecar (`Dockerfile.relay`), with QuantaSeek attached to the sidecar's namespace.
- **cryptoscan** `scan /t --format json --include-quantum-safe`. The flag puts quantum-safe hits (SHA-2, AES) on
  equal footing with pqcscan, which lists them.

## Row schema and the diff

Every tool's output becomes rows `{target, surface: tls|cert|code, algorithm, strength_bits|null, pq_safe: bool|null,
detail, source_tool}`. `pq_safe` is the tool's own verdict, `null` when it states none. The normaliser for each
tool reads its real output; samples are committed in `samples/` and covered by
`tests/benchmark/test_bakeoff_normalise.py`.

Dropped on purpose: pqcscan's marker findings that name no algorithm (`N/A`, `UNKNOWN`, `PKCS12-ENCRYPTED`) and its
"does not support TLS 1.3" absence finding; cryptoscan's `config` findings; a TLS 1.2 suite QuantaSeek cannot name
(`Unknown(0xc02f)`).

The diff key is `(target, surface, canonical(algorithm))`. `canonical` in `normalise.py` is the alias table:

- hybrid groups: `X25519MLKEM768` = `x25519_kyber768` = `X25519Kyber768Draft00` = `X25519ML-KEM-768`
- families: `RSA-2048` = `RSA`; `ECDSA-secp256r1` = `ECC` = `EC-SECP256R1`; `AES-256-GCM` = `AES`; `ChaCha20-Poly1305` = `ChaCha20`
- ML-DSA: `MLDSA65PublicKey` = `ML-DSA-65`; PQC library imports: `liboqs` / `pqcrypto` = `Post-Quantum Cryptography Library`
- TLS: `TLS 1.2` = `TLSv1.2`; OpenSSL and IANA suite names fold together, and a TLS 1.3 suite (`TLS_AES_256_GCM_SHA384`)
  stays apart from the TLS 1.2 RSA-key-exchange suite with the same tail (`AES256-GCM-SHA384`)
- kept apart: a signature scheme (`ECDSA-SHA256`) from a key (`ECDSA`), a bare named group (`secp256r1`) from an EC key,
  `AES-ECB` from the AES family, `DES` from `3DES`

Folding to a family hides a size difference (RSA-1024 against RSA-2048 is one key). `strength_bits` keeps the size in
the rows when a tool states it.

## Limits

- One run on one box, loopback only. Nothing here measures speed, scale or behaviour against real servers.
- `pq_safe` verdicts are each tool's own and are not compared; the diff is about what a tool reports, not whether it
  rates it the same way.
- A tool that cannot parse a file (anvil on TLS 1.2, cryptoscan on a DER certificate) reports nothing, not an error,
  and shows up as *pqcscan-only*.
- `commit` in `bakeoff.json` is the pqcscan source the probes ran on (the HEAD the scan started from); `runner_commit`
  is the commit of the runner and normalisers that produced the raw files. `--from-raw` rebuilds the tables with the
  current normalisers and does not change either.
- The `scope` of a tool (anvil: key-exchange groups only) is a judgement; the raw counts are shown next to the scoped ones.
