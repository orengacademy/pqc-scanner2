# Fuzz results: `load_bundle`, 4 CPU-hours, no crashes

Both atheris harnesses (see `README.md` for what each one feeds `load_bundle`) ran on a clean 8-vCPU droplet at
`006c78c`; the outputs are committed in `1dfc22f`. `src/pqcscan/store/bundle.py` and `src/pqcscan/core/parity.py` are
unchanged between `006c78c` and this commit, so the line numbers below point at the current code.

Command, from the repository root:

```bash
uv pip install -e ".[dev,verify]"
nohup bash benchmark/fleet/fuzz/run.sh 4 > benchmark/fleet/fuzz/run.log 2>&1 &
```

`run.sh 4` gives each harness 2 CPU-hours: `-jobs=4 -workers=4 -max_total_time=1800 -max_len=262144
-rss_limit_mb=4096 -timeout=30`, with `bundle.dict`, then merges each corpus and replays it under coverage.

## Per harness

| Harness | Workers x wall | CPU-hours | Executions | Executions per CPU-second | Crashes, OOMs, timeouts | Corpus files |
|---|---|---|---|---|---|---|
| `json` | 4 x 1,801 s | 2.0 | 81,812,235 | 11,357 | 0 | 40 |
| `raw` | 4 x 1,801 s | 2.0 | 507,885,114 | 70,500 | 0 | 6 |
| total | | 4.0 | 589,697,349 | | 0 | 46 |

Source: `stats.json` (`cpu_seconds` 7,204 per harness is the sum of the four jobs' `Done N runs in 1801 second(s)`
lines in `run.log`; all eight jobs exited with code 0).

**No crashes, so there is no `crashes/` directory and no fix commit.** A crash would have been any exception other
than `BundleInvalid` or `BundleTooLarge`, a single input running past 30 s, or RSS past 4 GB; none of the eight jobs
wrote a `crash-*`, `oom-*` or `timeout-*` artifact.

The merged corpora are in `corpus/json/` (40 files, seeds included) and `corpus/raw/` (6 files).

## Coverage of the merged corpus

From `coverage.txt` (`replay_coverage.sh`, line coverage):

| File | Statements | Missed | Cover |
|---|---|---|---|
| `src/pqcscan/store/bundle.py` | 105 | 19 | 82 % |
| `src/pqcscan/core/parity.py` | 66 | 44 | 33 % |

### Uncovered lines in `bundle.py`

| Lines | Code | Why the fuzzer does not reach it | Where it is tested instead |
|---|---|---|---|
| 62 | `_iso` body | only `dump_bundle` calls it | `test_round_trip` |
| 76 | `check_labels`: more than 64 labels | reachable from the JSON harness (65 short labels are about 600 bytes), but not found in 2 CPU-hours | `test_load_caps_host_labels`, `test_enroll_caps_host_labels` |
| 85-115 | `dump_bundle` | agent-side serializer; `load_bundle` never calls it | `tests/unit/test_bundle.py` round-trip tests |
| 120 | 8 MiB gzip cap | unreachable: `-max_len` keeps every input at or under 256 KiB | `test_load_rejects_oversize`, `test_load_size_caps_are_inclusive` |
| 128 | 50 MiB raw cap | the JSON harness cannot reach it (at most 256 KiB of text); the raw harness could only as a compression bomb, and libFuzzer did not assemble one | `test_load_rejects_oversize`, `test_load_size_caps_are_inclusive`, `test_load_inflates_a_bomb_no_further_than_the_cap` |
| 146 | 200,000-findings cap | the JSON harness would need at least 600 KB of text; the raw harness would need a gzip that inflates to that many findings | `test_load_rejects_too_many_findings`, `test_load_size_caps_are_inclusive` |

### Uncovered lines in `parity.py`

Lines 19, 33-43, 47-54, 66-73, 84-99, 103 and 110 are the bodies of `is_drift`, `_norm_token`, `_norm_title`,
`parity_key`, `drift_rows`, `_summary` and `_drift`. `load_bundle` imports only the `DRIFT_PROBE` constant from
`parity`; these functions run at ingest, in `Repo.ingest_bundle`, after the bundle has been loaded. They are outside
what a `load_bundle` harness can reach by design. `tests/unit/test_parity_drift.py` alone covers all 66 statements.

## Why `-max_len` is 256 KiB

A larger limit makes every execution slower, and the caps it would open up are already pinned by unit tests at their
exact boundaries. At 256 KiB the 8 MiB gzip cap is out of reach for both harnesses, the 50 MiB raw cap is reachable
only by the raw harness as a compression bomb, and the findings cap is out of reach in practice. The uncovered
lines 120, 128 and 146 above are this limit of the harness, not untested behaviour.

## Reproduce a finding

```bash
.venv/bin/python benchmark/fleet/fuzz/fuzz_load_bundle_<h>.py benchmark/fleet/fuzz/work/<h>/crash-<hash>
```
