# Mutation testing: fleet collector and bundle loader

mutmut 3.8.0 (the `verify` extra asks for `mutmut>=3.8`) mutates `src/pqcscan/daemon/fleet.py` and
`src/pqcscan/store/bundle.py` and re-runs the fleet test files for each mutant. A surviving mutant is a behaviour the unit
tests do not pin.

```bash
uv pip install -e ".[dev,verify]"
bash benchmark/fleet/mutation/run.sh            # hours; MUTMUT_CHILDREN=4 by default
```

**Do not run other tests in this checkout while it runs.** mutmut copies `src/` and `tests/` into `./mutants/`, puts
`mutants/src` first on `sys.path` and removes the real `src`; it also rewrites files under `mutants/` as it goes.
`run.sh` deletes `mutants/` first, so it always starts from scratch.

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
  no:cacheprovider` keeps pytest from writing caches into the copy. Checked locally: the stats pass completes and
  mutants get verdicts (447 mutants; stopped after 12).
- pytest's own `addopts` (`-m 'not fuzz'`) is left alone: no test in the selection is fuzz-marked, and mutmut adds
  its own `-x -q`.
- Only the config was verified here (it loads without warnings and lists exactly the two files); `mutmut run` was
  not started.
