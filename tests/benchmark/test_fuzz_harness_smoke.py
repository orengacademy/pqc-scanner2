"""The atheris harnesses start, replay the seeds and survive 200 mutated inputs. Proves the wiring, not the coverage."""
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("atheris", reason="needs the `verify` extra (atheris, Linux only)")

pytestmark = pytest.mark.benchmark

FUZZ = Path(__file__).resolve().parents[2] / "benchmark" / "fleet" / "fuzz"


@pytest.mark.parametrize("harness", ["json", "raw"])
def test_harness_runs_200_inputs_without_a_crash(tmp_path, harness):
    subprocess.run([sys.executable, str(FUZZ / "seed.py"), str(tmp_path / "seeds")], check=True, timeout=120)
    seeds = tmp_path / "seeds" / harness
    assert len(list(seeds.iterdir())) == 3
    r = subprocess.run(
        [sys.executable, str(FUZZ / f"fuzz_load_bundle_{harness}.py"), "-runs=200", f"-artifact_prefix={tmp_path}/",
         f"-dict={FUZZ / 'bundle.dict'}", str(seeds)],
        capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    assert not list(tmp_path.glob("crash-*"))
