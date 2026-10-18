# Mutation testing: fleet collector and bundle loader

mutmut 3.8.0 (the `verify` extra asks for `mutmut>=3.2`) mutates `src/pqcscan/daemon/fleet.py` and
`src/pqcscan/store/bundle.py` and re-runs `tests/unit` for each mutant. A surviving mutant is a behaviour the unit
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
- `pytest_add_cli_args_test_selection = ["tests/unit"]` replaces the deprecated `tests_dir`.
- pytest's own `addopts` (`-m 'not fuzz'`) is left alone: no test under `tests/unit` is fuzz-marked, and mutmut adds
  its own `-x -q`.
- Only the config was verified here (it loads without warnings and lists exactly the two files); `mutmut run` was
  not started.
