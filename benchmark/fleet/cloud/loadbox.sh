#!/usr/bin/env bash
# DigitalOcean load box for benchmark/fleet: create, run a suite, pull results, destroy.
#   loadbox.sh up            # create pqc-loadbox, wait for cloud-init (5-8 min), print IP
#   loadbox.sh run before    # any suite.sh mode (before|after|sweep|...): start it on the box (log: /root/suite.log)
#   loadbox.sh wait          # block until the suite finished; fails if it died or the box is unreachable
#   loadbox.sh pull          # rsync results/, profiles/, LOAD.md and the suite log into this checkout
#   loadbox.sh down          # destroy the droplet (it bills until you do)
# Env: DO_REGION=sgp1 DO_SIZE=s-8vcpu-16gb DO_IMAGE=ubuntu-24-04-x64 DO_SSH_KEY=pqc-campaign
#      PQC_REF=$(git rev-parse HEAD)  PQC_SSH_KEY=<private key path, passed as ssh -i>
# shellcheck disable=SC2016,SC2029  # remote commands are built client-side / single-quoted on purpose
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../../.." && pwd)
NAME=${DO_NAME:-pqc-loadbox}; REGION=${DO_REGION:-sgp1}; SIZE=${DO_SIZE:-s-8vcpu-16gb}
IMAGE=${DO_IMAGE:-ubuntu-24-04-x64}; KEY=${DO_SSH_KEY:-pqc-campaign}
# DigitalOcean recycles IPs between droplets, so a shared known_hosts would hold stale keys. The host key is
# therefore pinned per droplet: `up` starts a fresh file, accept-new trusts the first connection, `down` deletes it.
KNOWN="$HERE/.loadbox_known_hosts"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$KNOWN" -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=10)
[ -z "${PQC_SSH_KEY:-}" ] || SSH_OPTS+=(-i "$PQC_SSH_KEY")
ip() { doctl compute droplet list --format Name,PublicIPv4 --no-header | awk -v n="$NAME" '$1==n{print $2}'; }
host() { local h; h=$(ip); [ -n "$h" ] || { echo "no droplet named $NAME" >&2; return 1; }; echo "$h"; }
box() { local h; h=$(host) || return 1; ssh "${SSH_OPTS[@]}" "root@$h" "$@"; }
# Prints done|running|dead on the box; stderr stays out of the answer.
probe='if [ -f /root/SUITE_DONE ]; then echo done
  elif kill -0 "$(cat /root/suite.pid 2>/dev/null)" 2>/dev/null; then echo running
  elif [ -f /root/SUITE_DONE ]; then echo done
  else echo dead; fi'
still_billing="the droplet $NAME still exists and bills: inspect it, then run 'loadbox.sh down'"
case "${1:-}" in
  up)
    [ -z "$(ip)" ] || { echo "$NAME already exists ($(ip)); run 'loadbox.sh down' first" >&2; exit 2; }
    REF=$(git -C "$REPO" rev-parse "${PQC_REF:-HEAD}^{commit}")
    rm -f "$KNOWN"
    keyid=$(doctl compute ssh-key list --format ID,Name --no-header | awk -v k="$KEY" '$2==k{print $1}')
    [ -n "$keyid" ] || { echo "ssh key $KEY not in DigitalOcean (doctl compute ssh-key import)" >&2; exit 2; }
    doctl compute droplet create "$NAME" --region "$REGION" --size "$SIZE" --image "$IMAGE" --ssh-keys "$keyid" \
      --user-data "$(sed "s|@PQC_REF@|$REF|" "$HERE/loadbox-cloud-init.yaml")" --tag-name pqc-campaign --wait >/dev/null
    err=none
    for _ in $(seq 90); do
      sleep 10
      st=$(box 'if [ -f /root/FAILED ]; then echo "FAILED $(cat /root/FAILED)"; elif [ -f /root/READY ]; then echo "READY $(cat /root/READY)"; fi' 2>&1) || { err=$st; continue; }
      case $st in
        FAILED*) echo "cloud-init setup failed: ${st#FAILED }; see /var/log/cloud-init-output.log on the box; $still_billing" >&2; exit 1;;
        READY*) [ "${st#READY }" = "$REF" ] || { echo "box is at ${st#READY }, wanted $REF; $still_billing" >&2; exit 1; }
                host; exit 0;;
      esac
    done
    echo "cloud-init did not finish in 15 min (last ssh error: $err); $still_billing" >&2; exit 1;;
  run)
    mode=${2:-}
    # The modes are suite.sh's own: read from its argument check, so a mode added there needs no edit here.
    modes=$(sed -n 's/^case "${1:-}" in \([a-z|-]*\)) ;;.*/\1/p' "$HERE/suite.sh")
    [ -n "$modes" ] || { echo "cannot read the mode list from suite.sh's first case line" >&2; exit 2; }
    [[ -n $mode && "|$modes|" == *"|$mode|"* ]] || { echo "usage: loadbox.sh run $modes" >&2; exit 2; }
    box "set -e; cd /root/pqc-scanner2
      if [ -f /root/suite.pid ] && kill -0 \$(cat /root/suite.pid) 2>/dev/null; then echo 'a suite is already running' >&2; exit 3; fi
      rm -f /root/SUITE_DONE
      nohup bash benchmark/fleet/cloud/suite.sh $mode > /root/suite.log 2>&1 < /dev/null &
      echo \$! > /root/suite.pid
      echo started suite $mode, pid \$(cat /root/suite.pid)";;
  wait)
    fails=0
    while :; do
      if st=$(box "$probe" 2>&1); then
        fails=0
        case $st in
          *done) box tail -5 /root/suite.log; exit 0;;
          *dead) echo "suite process is gone without finishing; last log lines:" >&2; box tail -20 /root/suite.log >&2; exit 1;;
        esac
      else
        fails=$((fails + 1))
        if [ "$fails" -ge 5 ]; then echo "box unreachable 5 times in a row; last ssh error: $st; $still_billing" >&2; exit 1; fi
      fi
      sleep 60
    done;;
  pull)
    h=$(host); rsh="ssh ${SSH_OPTS[*]@Q}"
    for p in results/ profiles/ LOAD.md; do
      rsync -az -e "$rsh" "root@$h:/root/pqc-scanner2/benchmark/fleet/$p" "$REPO/benchmark/fleet/$p"
    done
    rsync -az -e "$rsh" "root@$h:/root/suite.log" "$HERE/last-suite.log" || echo "no /root/suite.log on the box" >&2;;
  down) doctl compute droplet delete -f "$NAME"; rm -f "$KNOWN";;
  *) sed -n 2,9p "$0"; exit 2;;
esac
