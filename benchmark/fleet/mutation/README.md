# Mutation testing: fleet collector and bundle loader

mutmut 3.8.0 (the `verify` extra asks for `mutmut>=3.8`) mutates `src/pqcscan/daemon/fleet.py` and
`src/pqcscan/store/bundle.py` and re-runs the fleet test files for each mutant. A surviving mutant is a behaviour the unit
tests do not pin.

`run.sh` expects the repo's virtualenv at `.venv/bin` (it puts that first on `PATH`), so create it there first:

```bash
python3 -m venv .venv                   # or: uv venv
uv pip install -e ".[dev,verify]"       # or: .venv/bin/pip install -e ".[dev,verify]"
bash benchmark/fleet/mutation/run.sh            # hours; MUTMUT_CHILDREN=4 by default
```

**Do not run other tests in this checkout while it runs.** mutmut copies `src/` and `tests/` into `./mutants/`, puts
`mutants/src` first on `sys.path` and removes the real `src`; it also rewrites files under `mutants/` as it goes.
`run.sh` deletes `mutants/` first, so it always starts from scratch.

`run.sh` does two things so that a long run does not die late:

- **Raises the open-file limit** to the hard limit, capped at 65536, and refuses to start if that did not take effect.
  mutmut 3 re-runs pytest in long-lived processes and the fleet tests leak descriptors (SQLite engines, temp dirs).
  With the usual soft limit of 1024 a droplet run got through the stats pass and then failed with `OSError: [Errno 24]
  Too many open files` while generating mutants, leaving every mutant "not checked".
- **Runs mutants in forked children** with `--max-children 4` (`MUTMUT_CHILDREN` to change it), so descriptors leaked by
  one mutant's test run die with its child.

If `mutmut run` fails, `run.sh` prints the last 20 lines of `run.log` and exits 1. It also exits 1 after writing
`score.json` if any mutant is still "not checked", so a failed run never looks like a slow one.

## Output

| File | Content |
|---|---|
| `run.log` | full mutmut output |
| `results.txt` | `mutmut results --all true`: `<mutant id>: <killed\|survived\|timeout\|suspicious\|no tests>` per mutant |
| `survivors/<id>.diff` | `mutmut show <id>` for every survived, suspicious or no-tests mutant |
| `score.json` | `killed`, `survived`, `timeout`, `suspicious`, `no_tests`, `total`, `score` (killed / total; timeouts are not counted as kills) |

To re-check one mutant after adding a test: `.venv/bin/mutmut run <id>` then `.venv/bin/mutmut show <id>`.

## The mutmut 3.8 CLI as used

`mutmut run [--max-children N] [MUTANT_NAMES]...`, `mutmut results [--all BOOLEAN]` (without `--all true` killed
mutants are omitted), `mutmut show MUTANT_NAME`, plus `apply`, `browse`, `export-cicd-stats`,
`print-time-estimates`, `tests-for-mutant`. There is no `--paths-to-mutate` or `--runner` flag as in mutmut 2; all
selection is in `[tool.mutmut]`.

## Config (`[tool.mutmut]` in `pyproject.toml`)

- `source_paths = ["src"]` and `only_mutate = [fleet.py, bundle.py]`. The task brief named `paths_to_mutate` with the
  two files; in 3.8 that key is deprecated and copies only the listed files into `mutants/`, so `import pqcscan`
  would fail. Copying all of `src` and restricting mutants with `only_mutate` mutates the same two files.
- `pytest_add_cli_args_test_selection` replaces the deprecated `tests_dir` and names the nine test files that exercise
  the two mutated modules (`test_daemon_fleet`, `test_fleet_repo`, `test_fleet_threat_model_gaps`, `test_bundle`,
  `test_fleet_schema`, `test_parity_drift`, `test_daemon_guard` under `tests/unit`; `test_daemon_api` and
  `test_fleet_spool` under `tests/integration`). Selecting all of `tests/unit` made the stats pass fail:
  `test_fleet_reconcile.py` does `import reconcile` through a `sys.path` hack that does not resolve from the
  `mutants/` copy, pytest stopped at that one collection error and mutmut reported "failed to collect stats". That
  test covers `benchmark/fleet/reconcile.py`, not the mutated code, so it is also passed `--ignore`. `-p
  no:cacheprovider` keeps pytest from writing caches into the copy.
- pytest's own `addopts` (`-m 'not fuzz'`) is left alone: no test in the selection is fuzz-marked, and mutmut adds
  its own `-x -q`.
- The full run went on a clean 8-vCPU droplet at `8457f85`: 447 mutants, 333 killed, 113 survived, 1 timeout, raw
  score 0.745 (`score.json`, outputs committed in `c8c31fc`). `MUTATION.md` grades every survivor.
