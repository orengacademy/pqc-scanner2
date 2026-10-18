#!/usr/bin/env bash
# Runs ON the load box. Usage: suite.sh before|after|sweep|ratio-baseline
# run_load exit 1 means a FAIL row or request errors: the suite goes on. Any other non-zero exit is a
# crash (traceback 1 is indistinguishable from exit 1 here; argparse 2, OOM 137, ...): counted and
# reported, and the suite goes on. /root/SUITE_DONE is always touched at the end.
set -euo pipefail
case "${1:-}" in before|after|sweep|ratio-baseline) ;; *) sed -n 2,2p "$0"; exit 2;; esac
cd /root/pqc-scanner2
PY=.venv/bin/python
rm -f /root/SUITE_DONE
trap 'touch /root/SUITE_DONE' EXIT
crashes=0
run() {
  local rc=0
  echo "== $*"
  $PY -m benchmark.fleet.run_load "$@" || rc=$?
  case $rc in
    0) ;;
    1) echo "run_load exit 1: FAIL row or request errors, see the row above";;
    *) echo "CRASH exit $rc"; crashes=$((crashes + 1));;
  esac
}
case "$1" in
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
esac
echo "suite $1 finished: $crashes crash(es)"
[ "$crashes" -eq 0 ]
