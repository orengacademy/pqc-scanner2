#!/usr/bin/env bash
# Real soak resource sampler: appends one CSV line to /var/lib/pqcscan-soak/samples.csv per call.
#   sampler.sh collector   # on the collector: DB and WAL size, host/scan/finding counts (read-only sqlite3)
#   sampler.sh agent       # on an agent: state dir size and spool depth
# Installed as /usr/local/sbin/pqc-soak-sampler with an /etc/cron.d entry every 10 minutes (as root, so it can read
# the pqcscan-owned 0700 state dir). Columns that do not apply to the role are left empty. `soak.sh collect` checks
# every pulled CSV's first line against HEADER below.
set -euo pipefail
HEADER="ts,role,load1,mem_used_kb,mem_avail_kb,disk_used_kb,db_bytes,wal_bytes,state_bytes,spool_files,hosts,scans,findings"
role=${1:-}
OUT=/var/lib/pqcscan-soak/samples.csv
DB=/var/lib/pqcscan/fleet.db
STATE=/var/lib/pqcscan/agent

ts=$(date -u +%FT%TZ)
load1=$(cut -d' ' -f1 /proc/loadavg)
# /proc/meminfo, not vmstat: vmstat has no "available" column. used = MemTotal - MemAvailable.
read -r mem_total mem_avail < <(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{print t, a}' /proc/meminfo)
mem_used=$((mem_total - mem_avail))
disk_used=$(df -k --output=used /var/lib | tail -1 | tr -d ' ')
db_bytes='' wal_bytes='' state_bytes='' spool_files='' hosts='' scans='' findings=''
case $role in
  collector)
    db_bytes=$(stat -c %s "$DB")
    wal_bytes=$(stat -c %s "$DB-wal" 2>/dev/null || echo 0)
    # mode=ro: the sampler never writes the live DB; .timeout rides out a write lock held by an ingest.
    counts=$(sqlite3 -readonly -cmd ".timeout 5000" "file:$DB?mode=ro" \
      "select (select count(*) from hosts), (select count(*) from scans), (select count(*) from findings)")
    IFS='|' read -r hosts scans findings <<< "$counts"
    ;;
  agent)
    state_bytes=$(du -sb "$STATE" | cut -f1)
    spool_files=0
    [ ! -d "$STATE/spool" ] || spool_files=$(find "$STATE/spool" -maxdepth 1 -name '*.bundle.gz' | wc -l)
    ;;
  *) echo "usage: sampler.sh collector|agent" >&2; exit 2;;
esac
mkdir -p "${OUT%/*}"
[ -s "$OUT" ] || echo "$HEADER" > "$OUT"
echo "$ts,$role,$load1,$mem_used,$mem_avail,$disk_used,$db_bytes,$wal_bytes,$state_bytes,$spool_files,$hosts,$scans,$findings" >> "$OUT"
