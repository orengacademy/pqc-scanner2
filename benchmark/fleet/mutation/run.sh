#!/usr/bin/env bash
# Mutation-test the fleet collector and the bundle loader with mutmut 3.
#
#   bash benchmark/fleet/mutation/run.sh            # MUTMUT_CHILDREN=4 bash ... to change the worker count
#
# Mutates src/pqcscan/daemon/fleet.py and src/pqcscan/store/bundle.py ([tool.mutmut] in pyproject.toml) against
# tests/unit. mutmut copies src/ and tests/ into ./mutants/ and runs pytest there, so do not run other tests in this
# checkout while it runs. Outputs (in benchmark/fleet/mutation/):
#   run.log              full mutmut output
#   results.txt          `mutmut results --all true`: one line per mutant, "<mutant id>: <status>"
#   survivors/<id>.diff  `mutmut show <id>` for every survived, suspicious or no-tests mutant
#   score.json           {killed, survived, timeout, suspicious, no_tests, total, score}; score = killed / total
set -euo pipefail
MUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$MUT/../../.." && pwd)"
cd "$REPO"
export PATH="$REPO/.venv/bin:$PATH"

rm -rf mutants "$MUT/survivors"
mkdir -p "$MUT/survivors"
mutmut run --max-children "${MUTMUT_CHILDREN:-4}" 2>&1 | tee "$MUT/run.log"
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
PYEOF
