#!/usr/bin/env bash
# Download OSV.dev advisory snapshot(s) and concatenate to a single
# JSONL file consumable by pqcscan.probes.cve_osv_offline.
#
# Usage:
#   bash scripts/fetch-osv-snapshot.sh                    # PyPI + npm + Go (default)
#   bash scripts/fetch-osv-snapshot.sh PyPI               # one ecosystem
#   bash scripts/fetch-osv-snapshot.sh --all              # every ecosystem (~1+ GB)
#   bash scripts/fetch-osv-snapshot.sh --out /var/lib/pqcscan/osv-snapshot.jsonl
#                                                         # custom output path
#
# Where to put the output:
#   - Default: <repo>/var/osv-snapshot.jsonl
#   - Production: /var/lib/pqcscan/osv-snapshot.jsonl  (the path
#     cve.osv_offline checks if PQCSCAN_OSV_SNAPSHOT isn't set).
#   - Or set PQCSCAN_OSV_SNAPSHOT=<path> to point the probe anywhere.
#
# Network: ~25 MB per common ecosystem (PyPI, npm, Go) — small enough
# to commit to a CI cache. The --all switch downloads every ecosystem
# OSV.dev hosts (~1 GB total).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/var/osv-snapshot.jsonl"
TMP="${TMPDIR:-/tmp}/pqcscan-osv-fetch.$$"

ECOSYSTEMS=()
ALL_KNOWN=(
  PyPI npm Go crates.io Packagist RubyGems NuGet Hex Pub Maven
  Hackage OSS-Fuzz Linux GHC GitHub-Actions UVI
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)        OUT="$2"; shift 2 ;;
    --all)        ECOSYSTEMS=("${ALL_KNOWN[@]}"); shift ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    -*)           echo "error: unknown flag $1" >&2; exit 2 ;;
    *)            ECOSYSTEMS+=("$1"); shift ;;
  esac
done

# Default ecosystem set when none specified: the three highest-traffic
# language ecosystems. Covers the bulk of typical scan targets.
if [[ ${#ECOSYSTEMS[@]} -eq 0 ]]; then
  ECOSYSTEMS=(PyPI npm Go)
fi

mkdir -p "$(dirname "$OUT")" "$TMP"
trap 'rm -rf "$TMP"' EXIT

echo "→ Output: $OUT"
echo "→ Ecosystems: ${ECOSYSTEMS[*]}"
: > "$OUT"

total=0
for eco in "${ECOSYSTEMS[@]}"; do
  url="https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip"
  zip_path="$TMP/${eco}.zip"
  extract_dir="$TMP/${eco}.d"
  mkdir -p "$extract_dir"

  echo "  ⇣ $eco — downloading $url"
  if ! curl -sSfL -o "$zip_path" "$url"; then
    echo "    ✘ download failed for $eco; skipping" >&2
    continue
  fi
  unzip -q "$zip_path" -d "$extract_dir"
  count=$(find "$extract_dir" -type f -name '*.json' | wc -l)
  echo "    ✓ $count records"

  # Concatenate every JSON record on its own line.
  python3 - "$OUT" "$extract_dir" <<'PY'
import glob, json, sys
out_path, extract_dir = sys.argv[1], sys.argv[2]
out = open(out_path, 'a', encoding='utf-8')
n = 0
for p in glob.glob(f'{extract_dir}/*.json'):
    try:
        rec = json.load(open(p))
    except (OSError, json.JSONDecodeError):
        continue
    out.write(json.dumps(rec) + '\n')
    n += 1
out.close()
print(f'    ↪ appended {n} records to snapshot')
PY
  total=$((total + count))
done

bytes=$(wc -c < "$OUT")
echo
if command -v numfmt >/dev/null 2>&1; then
  size=$(numfmt --to=iec --suffix=B "$bytes")
else
  size="${bytes} bytes"
fi
echo "OK — $total records, $size at $OUT"
echo
echo "Set PQCSCAN_OSV_SNAPSHOT=$OUT (or copy to /var/lib/pqcscan/osv-snapshot.jsonl)"
echo "to activate the cve.osv_offline matcher against this snapshot."
