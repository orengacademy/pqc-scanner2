#!/usr/bin/env bash
# Mutation-test the fleet collector and the bundle loader with mutmut 3.
#
#   bash benchmark/fleet/mutation/run.sh            # MUTMUT_CHILDREN=4 bash ... to change the worker count
#
# Mutates src/pqcscan/daemon/fleet.py and src/pqcscan/store/bundle.py ([tool.mutmut] in pyproject.toml) against
# the fleet test files (see README). mutmut copies src/ and tests/ into ./mutants/ and runs pytest there, so do not
# run other tests in this checkout while it runs. Outputs (in benchmark/fleet/mutation/):
#   run.log              full mutmut output
#   results.txt          `mutmut results --all true`: one line per mutant, "<mutant id>: <status>"
#   survivors/<id>.diff  `mutmut show <id>` for every survived, suspicious or no-tests mutant
#   score.json           {killed, survived, timeout, suspicious, no_tests, total, score}; score = killed / total
set -euo pipefail
MUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$MUT/../../.." && pwd)"
cd "$REPO"
export PATH="$REPO/.venv/bin:$PATH"

# mutmut 3 re-runs pytest in long-lived processes and the fleet tests leak descriptors (SQLite engines, temp dirs), so a
# default soft limit of 1024 runs out ("Too many open files") and every mutant stays "not checked". Raise it to the
# hard limit, capped at 65536, and refuse to start if that did not take effect.
want=65536
hard="$(ulimit -Hn)"
if [ "$hard" != "unlimited" ] && [ "$hard" -lt "$want" ]; then want="$hard"; fi
ulimit -Sn "$want" || true
if [ "$(ulimit -n)" != "$want" ]; then
  echo "run.sh: could not raise the open-file limit to $want (now $(ulimit -n), hard $hard); raise it and retry" >&2
  exit 1
fi
echo "run.sh: open-file limit $(ulimit -n), mutmut children ${MUTMUT_CHILDREN:-4}"

rm -rf mutants "$MUT/survivors"
mkdir -p "$MUT/survivors"
# --max-children makes mutmut run each mutant in a forked child, so descriptors leaked by a test die with the child.
# A failed run must never look like a slow one: exit non-zero and show the end of the log.
if ! mutmut run --max-children "${MUTMUT_CHILDREN:-4}" 2>&1 | tee "$MUT/run.log"; then
  echo "run.sh: mutmut run FAILED; last 20 lines of $MUT/run.log:" >&2
  tail -n 20 "$MUT/run.log" >&2
  exit 1
fi
mutmut results --all true > "$MUT/results.txt"

python - "$MUT" <<'PYEOF'
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

mut = Path(sys.argv[1])
status = {}
for line in (mut / "results.txt").read_text().splitlines():
    m = re.match(r"^\s+(\S+): (.+)$", line)
    if m:
        status[m.group(1)] = m.group(2).strip()
n = Counter(status.values())
total = len(status)
score = {"killed": n["killed"], "survived": n["survived"], "timeout": n["timeout"], "suspicious": n["suspicious"],
         "no_tests": n["no tests"], "total": total, "score": round(n["killed"] / total, 4) if total else 0.0}
(mut / "score.json").write_text(json.dumps(score, indent=2) + "\n")
for mid, st in status.items():
    if st in ("survived", "suspicious", "no tests"):
        diff = subprocess.run(["mutmut", "show", mid], capture_output=True, text=True, check=True).stdout
        (mut / "survivors" / f"{mid}.diff").write_text(diff)
print(json.dumps(score, indent=2))
unchecked = n["not checked"] + n["check was interrupted by user"]
if not total or unchecked:
    sys.exit(f"run.sh: {unchecked} of {total} mutants were never checked; see run.log")
PYEOF
