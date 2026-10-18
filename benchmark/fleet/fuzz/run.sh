#!/usr/bin/env bash
# Fuzz load_bundle with both atheris harnesses, merge the corpora, replay them for coverage, write stats.json.
#
#   bash benchmark/fleet/fuzz/run.sh [cpu_hours]        # default 4
#
# cpu_hours is split between the two harnesses. Each runs -jobs=4 -workers=4, so it burns 4 CPU-seconds per wall
# second: wall time per harness = cpu_hours * 3600 / 2 / 4 seconds. Outputs (under benchmark/fleet/fuzz/):
#   work/<h>/        fuzzer corpus, crash-*/oom-*/timeout-* artifacts and the per-job fuzz-N.log files
#   corpus/<h>/      the merged, minimised corpus (seeds included), kept in git
#   coverage.txt     bundle.py and parity.py line coverage of the merged corpus
#   stats.json       per harness: cpu_seconds, execs, crashes, corpus_files
# <h> is `json` (fuzz_load_bundle_json.py) or `raw` (fuzz_load_bundle_raw.py).
set -euo pipefail
FUZZ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$FUZZ/../../.." && pwd)"
PY="$REPO/.venv/bin/python"
# -jobs and -merge re-exec the harness script itself (shebang `env python3`), so the venv must lead PATH.
export PATH="$REPO/.venv/bin:$PATH"
H="${1:-4}"
SECS="$(awk -v h="$H" 'BEGIN { s = int(h * 3600 / 2 / 4); print (s < 1 ? 1 : s) }')"
cd "$FUZZ"
"$PY" seed.py seeds

for h in json raw; do
  W="$FUZZ/work/$h"
  mkdir -p "$W/corpus" "$FUZZ/corpus/$h"
  rm -f "$W"/fuzz-*.log
  # libFuzzer writes fuzz-N.log for each -jobs worker into its cwd, so run from the work dir.
  ( cd "$W" && "$FUZZ/fuzz_load_bundle_$h.py" "$W/corpus" "$FUZZ/seeds/$h" \
      -dict="$FUZZ/bundle.dict" -jobs=4 -workers=4 -max_total_time="$SECS" -max_len=262144 \
      -rss_limit_mb=4096 -timeout=30 -artifact_prefix="$W/" ) || echo "fuzz $h exited $? (crash artifacts are in $W)"
  "$FUZZ/fuzz_load_bundle_$h.py" -merge=1 "$FUZZ/corpus/$h" "$W/corpus" "$FUZZ/seeds/$h"
done

bash "$FUZZ/replay_coverage.sh"

"$PY" - "$FUZZ" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

fuzz = Path(sys.argv[1])
out = []
for h in ("json", "raw"):
    work = fuzz / "work" / h
    execs = cpu = 0
    for log in sorted(work.glob("fuzz-*.log")):
        text = log.read_text(errors="replace")
        done = re.findall(r"^Done (\d+) runs in (\d+) second", text, re.M)       # one per finished job
        if done:
            execs += int(done[-1][0])
            cpu += int(done[-1][1])
        else:                                                                    # job killed before "Done"
            status = re.findall(r"^#(\d+)\s", text, re.M)
            execs += int(status[-1]) if status else 0
    crashes = sum(1 for p in work.iterdir() if re.match(r"(crash|oom|timeout)-", p.name))
    out.append({"harness": h, "cpu_seconds": cpu, "execs": execs, "crashes": crashes,
                "corpus_files": sum(1 for _ in (fuzz / "corpus" / h).iterdir())})
(fuzz / "stats.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps(out, indent=2))
PYEOF
