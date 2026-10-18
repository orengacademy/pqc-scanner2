#!/usr/bin/env bash
# Runs ON the load box. Usage: suite.sh before|after|sweep|ratio-baseline
# A FAIL row makes run_load exit 1; the suite goes on and always touches /root/SUITE_DONE.
set -euo pipefail
cd /root/pqc-scanner2
PY=.venv/bin/python
rm -f /root/SUITE_DONE
trap 'touch /root/SUITE_DONE' EXIT
run() { echo "== $*"; $PY -m benchmark.fleet.run_load "$@" || echo "run_load exit $? (FAIL row recorded)"; }
case "${1:-}" in
  before|after)  # 4 posts/s with 1,670-finding bundles saturates both backends
    for db in sqlite postgres; do
      run --db "$db" --hosts 500 --rate 4 --duration 300s --profile "benchmark/fleet/profiles/$db-$1" --tag "$1"
    done;;
  sweep)
    for db in sqlite postgres; do
      for rate in 0.5 1 2 4 6 8 12; do
        for seed in 1 2; do
          run --db "$db" --hosts 500 --rate "$rate" --duration 300s --seed "$seed" --tag sweep
        done
      done
      run --db "$db" --herd --hosts 500 --duration 180s --seed 1 --tag herd
    done;;
  ratio-baseline)  # the CI job's shape
    for db in sqlite postgres; do
      run --db "$db" --hosts 120 --interval 60 --duration 90s --findings-per-bundle 1670 --tag ci-shape
    done;;
  *) sed -n 2,2p "$0"; exit 2;;
esac
