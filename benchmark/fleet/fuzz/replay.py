"""Replay a fuzz corpus through load_bundle once, for coverage. Run under `coverage run -m` from the repo root:

    coverage run --include='src/pqcscan/store/bundle.py,src/pqcscan/core/parity.py' \
        -m benchmark.fleet.fuzz.replay benchmark/fleet/fuzz/corpus

Layout is corpus/<harness>/<files>: `raw` files are the gzip body as fuzzed, `json` files are JSON text and are
gzipped here, as fuzz_load_bundle_json.py does. Prints the file count and how many load_bundle accepted.
"""
import gzip
import sys
from pathlib import Path

from pqcscan.store.bundle import BundleInvalid, BundleTooLarge, load_bundle


def replay(corpus: Path) -> tuple[int, int]:
    files = accepted = 0
    for harness in sorted(p for p in corpus.iterdir() if p.is_dir()):
        for f in sorted(harness.iterdir()):
            data = f.read_bytes()
            files += 1
            try:
                load_bundle(gzip.compress(data, compresslevel=1) if harness.name == "json" else data)
                accepted += 1
            except (BundleInvalid, BundleTooLarge):
                pass
    return files, accepted


if __name__ == "__main__":
    n, ok = replay(Path(sys.argv[1]))
    print(f"replayed {n} corpus files, {ok} accepted by load_bundle")
