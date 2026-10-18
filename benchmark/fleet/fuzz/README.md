# Fuzzing `load_bundle` with atheris

Two libFuzzer targets (atheris 3.0.0, `verify` extra, Linux only) drive `pqcscan.store.bundle.load_bundle`, the
function every fleet bundle passes through before anything is stored. `BundleInvalid` and `BundleTooLarge` are the
expected rejections; any other exception, a hang past 30 s, or an RSS past 4 GB is a finding.

| Harness | Input is | Reaches |
|---|---|---|
| `fuzz_load_bundle_json.py` (`<h>` = `json`) | bundle JSON text, gzipped by the harness | JSON parser, schema checks, labels, findings filtering |
| `fuzz_load_bundle_raw.py` (`<h>` = `raw`) | the gzip body itself | gzip framing, truncation check, size caps, then the same |

`pqcscan.store.bundle` and `pqcscan.core.parity` are instrumented. `load_bundle` imports only `DRIFT_PROBE` from
`parity`, so coverage of `parity.py` stays at its import-time lines; the figure that matters is `bundle.py`.

## Input size limit and which caps it can reach

Both harnesses run with `-max_len=262144` (256 KiB per input), which keeps executions fast. That bounds what they can
reach in `load_bundle`:

| Cap | JSON harness | Raw harness |
|---|---|---|
| `len(data) > MAX_GZIP_BYTES` (8 MiB gzip) | unreachable | unreachable |
| 50 MiB raw cap (`MAX_RAW_BYTES`) | unreachable: the input is at most 256 KiB of text | reachable only as a compression bomb: a gzip body of at most 256 KiB can inflate past 50 MiB |
| `MAX_FINDINGS` (200,000) | unreachable: 200,000 findings need at least 600 KB of JSON | only through a gzip that inflates to that many findings, which the fuzzer would have to assemble |

So the `BundleTooLarge` raises for the gzip size and, in practice, the findings count show as uncovered lines in
`coverage.txt`. They are a limit of the harness, not untested behaviour: the unit tests in `tests/unit/test_bundle.py`
cover the caps. Only the raw harness exercises the decompression cap.

## Run

```bash
uv pip install -e ".[dev,verify]"
nohup bash benchmark/fleet/fuzz/run.sh 4 > benchmark/fleet/fuzz/run.log 2>&1 &    # 4 CPU-hours
```

`run.sh [cpu_hours]` splits the hours between the harnesses. Each runs `-jobs=4 -workers=4`, so wall time per
harness is `cpu_hours * 3600 / 2 / 4` seconds (1800 s per harness for 4 CPU-hours, so about an hour in all). It then merges each corpus
(`-merge=1`) into `corpus/<h>/`, replays the merged corpus under coverage and writes `coverage.txt` and
`stats.json`. Use a small value such as `0.01` to check the wiring (about 25 s).

| Path | Content |
|---|---|
| `seeds/<h>/` | 3 valid documents from `_bundles.build_template(n_findings=3)`: with labels, with views, `status: failed`. Written by `seed.py`; the json seeds are text, the raw seeds gzipped. Not committed |
| `bundle.dict` | JSON keys and a few values `load_bundle` reads |
| `work/<h>/` | live corpus, `crash-*`/`oom-*`/`timeout-*` artifacts, per-job `fuzz-N.log`. Not committed |
| `corpus/<h>/` | merged corpus including the seeds |
| `coverage.txt` | `coverage report -m` for `bundle.py` and `parity.py` over `corpus/` |
| `stats.json` | list of `{harness, cpu_seconds, execs, crashes, corpus_files}`; `cpu_seconds` and `execs` sum each job's final `Done N runs in S second(s)` line |

`replay_coverage.sh` can be rerun on its own at any time. `-jobs` and `-merge` re-run the harness script, so the
scripts are executable with an `env python3` shebang and `run.sh` puts `.venv/bin` first on `PATH`.

To reproduce a crash: `.venv/bin/python benchmark/fleet/fuzz/fuzz_load_bundle_<h>.py work/<h>/crash-<hash>`.
Smoke test: `tests/benchmark/test_fuzz_harness_smoke.py` runs each harness for 200 inputs.
