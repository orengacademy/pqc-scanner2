#!/usr/bin/env bash
# Replay fuzz/corpus through load_bundle under coverage; writes fuzz/coverage.txt (line coverage, missing lines).
set -euo pipefail
FUZZ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$FUZZ/../../.." && pwd)"
cd "$REPO"
rm -f .coverage.fuzz
COVERAGE_FILE=.coverage.fuzz .venv/bin/coverage run \
  --include='src/pqcscan/store/bundle.py,src/pqcscan/core/parity.py' \
  -m benchmark.fleet.fuzz.replay "$FUZZ/corpus"
COVERAGE_FILE=.coverage.fuzz .venv/bin/coverage report -m > "$FUZZ/coverage.txt"
rm -f .coverage.fuzz
cat "$FUZZ/coverage.txt"
