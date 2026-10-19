#!/usr/bin/env bash
# Runs ON the load box. Usage: suite.sh before|after|sweep|ratio-baseline|pg-insert|retention
# run_load exit 1 means a FAIL row or request errors: the suite goes on. Any other non-zero exit is a
# crash (traceback 1 is indistinguishable from exit 1 here; argparse 2, OOM 137, ...): counted and
# reported, and the suite goes on. /root/SUITE_DONE is always touched at the end.
set -euo pipefail
case "${1:-}" in before|after|sweep|ratio-baseline|pg-insert|retention) ;; *) sed -n 2,2p "$0"; exit 2;; esac
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
  sweep)  # the CAPACITY.md shape. Per-host interval = hosts / rate must stay under half the 300 s run, or Little's
    # law cannot be checked: 60 hosts at 0.5/s (120 s), 100 at 1/s (100 s), 250 at 2/s (125 s), 300 at 3/s (100 s),
    # 500 hosts (125 s or less) from 4/s up
    for db in sqlite postgres; do
      for rate in 0.5 1 2 3 4 6 8 12; do
        case $rate in 0.5) hosts=60;; 1) hosts=100;; 2) hosts=250;; 3) hosts=300;; *) hosts=500;; esac
        for seed in 1 2; do
          run --db "$db" --hosts "$hosts" --rate "$rate" --duration 300s --seed "$seed" --tag sweep
        done
      done
      run --db "$db" --herd --hosts 500 --duration 180s --seed 1 --tag herd
    done
    # Postgres only: does a wider ingest gate move the saturation point? (the shipped default is 2 slots)
    for rate in 4 6; do
      for slots in 2 4 8; do
        run --db postgres --hosts 500 --rate "$rate" --duration 300s --seed 1 --ingest-parallelism "$slots" --tag par
      done
    done;;
  pg-insert)  # Postgres: multi-row INSERT pages against one parameter set per row, at the saturating rate
    for mode in pages executemany; do
      for slots in 2 4; do
        run --db postgres --hosts 500 --rate 4 --duration 300s --seed 1 --insert-mode "$mode" \
          --ingest-parallelism "$slots" --tag pginsert
      done
    done;;
  retention)  # keep 2, so prune_host runs from each host's third post; same shapes as the sweep's 1 and 0.5 posts/s
    for seed in 1 2; do
      run --db sqlite --hosts 100 --rate 1 --duration 300s --seed "$seed" --keep-scans-per-host 2 --tag retention
      run --db postgres --hosts 60 --rate 0.5 --duration 300s --seed "$seed" --keep-scans-per-host 2 --tag retention
    done;;
  ratio-baseline)  # the CI load-ratio job's shape (verify.yml): 60 hosts at 1 post/s
    for db in sqlite postgres; do
      run --db "$db" --hosts 60 --interval 60 --duration 120s --findings-per-bundle 1670 --tag ci-shape
    done;;
esac
echo "suite $1 finished: $crashes crash(es)"
[ "$crashes" -eq 0 ]
