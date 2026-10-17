# Accuracy benchmark harness

Measures pqcscan's detection **precision** and **recall** against a labelled
fixture corpus, and gates precision in CI so a false-positive regression can
never land silently. It turns "accurate" from an asserted claim into a measured
number.

## What it measures

Each case in `corpus/manifest.yaml` labels a fixture as `positive` (the probe
**should** fire) or `negative` (the probe should **not** fire). The runner
points the probe at the fixture, collects its findings, and scores:

| | probe fired | probe silent |
|---|---|---|
| **positive** | TP | FN |
| **negative** | FP | TN |

- `precision = TP / (TP + FP)` — of everything flagged, how much was real.
- `recall = TP / (TP + FN)` — of everything weak, how much we caught.

Division by zero is reported as `n/a` (a probe with no positive cases has no
recall; a probe that predicted nothing positive has no precision).

## The "real detection" scoring rule

A probe frequently emits non-detection findings: `INFO` / `ERROR` markers
(`platform_info`, `skipped`, `no X observed`) and `PQC_READY` findings (material
that is already quantum-safe). **None of those count as firing.**

A probe is scored as having *fired* only when it emits at least one finding
whose `classification` is a real weak / quantum-vulnerable tier:

```
{ sangat-tinggi, tinggi, sederhana, rendah }
```

equivalently `severity.numeric >= LOW and classification != INFO`. This is
implemented once in `run_benchmark.is_real_detection()`.

For a positive case an optional `expect` block refines what counts as a correct
fire — `algorithm_contains` (case-insensitive substring on a fired
`finding.algorithm`) and/or `min_severity`. A fire that does not satisfy the
refinement is recorded as an FN annotated *"fired but wrong algorithm/severity"*,
never as a TP.

## Current measured numbers

Corpus: **117 cases — 69 positive / 48 negative**, across 27 probes in 9 families.

```
OVERALL   TP=68  FP=0  FN=1  TN=48   precision=1.000   recall=0.986
```

The per-family table, the probes that were fixed, and the corpus limits are in
[`docs/ACCURACY.md`](../docs/ACCURACY.md). Full per-probe, per-family and
per-case numbers are written to `benchmark/last_report.json` on every run.

## Fixture kinds

A manifest case may set `fixture:` (default `file`):

- `file` — `input` is a file or directory handed to the probe as its roots.
- `endpoint` — `input` is an `endpoint.yaml` (`cert`, `key`, `min_version`,
  `max_version`, optional `ciphers`, `group`, `require_client_cert`,
  `requires_openssl`). The harness serves TLS from it on a free 127.0.0.1 port
  for the case and binds the probe to it the way `--target` does
  (`runner.bind_context`).
- `image` — `input` is an OCI image layout; its layers are extracted into a
  temp rootfs and the file probes are pointed at it.

A case the host cannot serve (an endpoint needing a newer OpenSSL) is reported
as `SKIP` and left out of every count.

## Coverage

- `code.ts.python` (stdlib-`ast` engine): real `hashlib.md5`, aliased
  `import hashlib as h; h.sha1`, `rsa.generate_private_key(key_size=2048)`,
  `DES.new`, classical EC keygen — plus negatives for a weak token in a comment,
  in a string literal, and a clean `hashlib.sha256` file.
- `code.ts.go / .java / .javascript / .php / .rust` (comment/string
  suppressor): each has a real weak call as a positive and the same token buried
  in a `// comment` and a `"string"` as negatives (plus clean-hash negatives for
  Go/JS).
- `fs.conf.f5 / .netscaler / .nginx / .haproxy / .sshd`: a weak config positive
  and a hardened-config negative each (NetScaler also has a weak-cipher-binding
  positive).
- `fs.cert.x509`: a weak RSA-1024 cert positive and an ML-DSA-65 (PQC, →
  `pqc-ready`) negative. Certs are generated with `cryptography` at authoring
  time and committed as PEM.
- `fs.db.crypto`: a SQLite DB with an RSA-2048 PEM cert in a TEXT column
  (positive) and a SQLite DB of ordinary text (negative). Built with stdlib
  `sqlite3` at authoring time and committed.
- Fleet-evidence extension: RSA-2048/3072/4096, ECDSA P-256/P-384 and Ed25519
  certs in PEM and DER (`fs.cert.x509`); PKCS#12 keystores and truststores
  (`fs.keystore.pkcs12`); PKCS#8, PKCS#1 and encrypted private keys
  (`fs.cert.privkey`, `fs.cert.privkey_encrypted`); OpenSSH host keys and
  `authorized_keys` (`fs.ssh.host_keys`); C#, Rust and Kotlin snippets; eight
  local TLS endpoints (TLS 1.0-only, static-RSA-only, NULL cipher, TLS 1.2
  ECDHE, mTLS, TLS 1.3 X25519, two hybrid X25519MLKEM768) against the six
  `net.tls.*` probes; two OCI images (OpenSSL 1.0.2 vs 3.5) against
  `fs.binary.crypto`, `fs.conf.openssl_cnf` and `sbom.crypto_map`.

Probes that need a running daemon (docker, syft) or host-only artefacts
(`host.*`) are excluded — they cannot be pointed at a fixture. TLS probes are
covered through local `endpoint` fixtures.

## How to run

```bash
source .venv/bin/activate

# print the table (+ writes last_report.json)
PYTHONPATH=src python benchmark/run_benchmark.py

# add the per-family table (the docs/ACCURACY.md run)
PYTHONPATH=src python benchmark/run_benchmark.py --by-family

# regenerate fixtures and CORPUS.sha256 (deterministic; --hash = hash only)
PYTHONPATH=src python benchmark/corpus/generate_fixtures.py

# JSON to stdout
PYTHONPATH=src python benchmark/run_benchmark.py --json

# CI-style gate: non-zero exit if thresholds are not met
PYTHONPATH=src python benchmark/run_benchmark.py --min-precision 1.0 --min-recall 0.95
```

The pytest regression gate lives at `tests/benchmark/test_accuracy.py`:

```bash
PYTHONPATH=src python -m pytest tests/benchmark/ -q
```

It asserts overall **precision == 1.0** (the zero-false-positive guarantee) and
**recall >= 0.95**, and checks that every manifest input exists and every probe
id resolves so the corpus cannot rot. It also checks that `corpus/CORPUS.sha256`
matches the fixtures and that the first line of `docs/ACCURACY.md` names the
current corpus hash.

## How to add a case

1. Add the fixture to `corpus/generate_fixtures.py` (it writes `corpus/cases/`).
   Code probes walk a directory, so a `code.ts.*` case is a **directory**
   holding one source file; the config / cert / DB probes take a single file
   (certs are directories because the cert probe walks a tree). Keep fixtures
   tiny and derive keys from a fixed seed.
2. Add an entry to `corpus/manifest.yaml` with a unique `id`, the real `probe`
   id (must resolve in `default_registry()`), `kind`, `input` (path relative to
   `corpus/`), optional `fixture`, and — for positives — an optional `expect`
   block.
3. Regenerate (`generate_fixtures.py`, which rewrites `CORPUS.sha256`), re-run
   with `--by-family`, confirm precision stays 1.0, and refresh
   `docs/ACCURACY.md`.

## Development notes

- Ruff + mypy clean, line length 120:
  ```bash
  ruff check benchmark/ tests/benchmark/
  MYPYPATH=src mypy benchmark/run_benchmark.py
  ```
  (`MYPYPATH=src` is the type-check analog of the `PYTHONPATH=src` run
  convention — the installed `pqcscan` ships no `py.typed` marker, so mypy needs
  the source tree on its path to see the real types.)
- Pure stdlib plus already-present deps (`pyyaml`, `cryptography`); no new
  dependencies. The harness is additive and read-only against `src/pqcscan` —
  it imports probes but never modifies them.

## Known misclassifications

One: `ep-mtls-https`. `net.tls.https` cannot finish a handshake with a server
that requires a client certificate, so it never sees the server cert;
`net.tls.cert_chain` does (see `docs/ACCURACY.md`).

A design note worth recording (not a bug): under the "real detection" rule,
`tinggi`-tier findings count as fires, so a *classical-but-modern* certificate
(ECDSA-P384, Ed25519) is correctly a detection, not a clean negative — those
keys are quantum-vulnerable (Shor). The only certificate that is genuinely *not*
flagged weak is a PQC one, which is why the `fs.cert.x509` negative is an
ML-DSA-65 cert (classified `pqc-ready`). Likewise a hardened SSH/TLS config
negative must avoid even modern-but-quantum-vulnerable tokens (e.g. `ssh-ed25519`
host keys, ECDHE cipher suites) to stay silent; the hardened fixtures use
PQC-neutral tokens that classify to `info`.
