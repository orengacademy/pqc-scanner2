#!/usr/bin/env bash
# DigitalOcean load box for benchmark/fleet: create, run a suite, pull results, destroy.
#   loadbox.sh up            # create pqc-loadbox, wait for cloud-init, print IP
#   loadbox.sh run before    # run suite.sh <mode> on the box (nohup; log in /root/suite.log)
#   loadbox.sh wait          # block until the suite finished
#   loadbox.sh pull          # rsync results/, profiles/ and LOAD.md into this checkout
#   loadbox.sh down          # destroy the droplet
# Env: DO_REGION=sgp1 DO_SIZE=s-8vcpu-16gb DO_IMAGE=ubuntu-24-04-x64 DO_SSH_KEY=pqc-campaign
#      PQC_REF=$(git rev-parse HEAD)  PQC_SSH_KEY=<private key path, passed as ssh -i>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../../.." && pwd)
NAME=${DO_NAME:-pqc-loadbox}; REGION=${DO_REGION:-sgp1}; SIZE=${DO_SIZE:-s-8vcpu-16gb}
IMAGE=${DO_IMAGE:-ubuntu-24-04-x64}; KEY=${DO_SSH_KEY:-pqc-campaign}
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
[ -z "${PQC_SSH_KEY:-}" ] || SSH_OPTS+=(-i "$PQC_SSH_KEY")
ip() { doctl compute droplet list --format Name,PublicIPv4 --no-header | awk -v n="$NAME" '$1==n{print $2}'; }
# shellcheck disable=SC2029  # remote command is built client-side on purpose
box() { ssh "${SSH_OPTS[@]}" "root@$(ip)" "$@"; }
case "${1:-}" in
  up)
    REF=${PQC_REF:-$(git -C "$REPO" rev-parse HEAD)}
    keyid=$(doctl compute ssh-key list --format ID,Name --no-header | awk -v k="$KEY" '$2==k{print $1}')
    [ -n "$keyid" ] || { echo "ssh key $KEY not in DigitalOcean (doctl compute ssh-key import)"; exit 2; }
    init=$(mktemp); trap 'rm -f "$init"' EXIT
    sed "s|@PQC_REF@|$REF|" "$HERE/loadbox-cloud-init.yaml" > "$init"
    doctl compute droplet create "$NAME" --region "$REGION" --size "$SIZE" --image "$IMAGE" --ssh-keys "$keyid" \
      --user-data-file "$init" --tag-name pqc-campaign --wait >/dev/null
    for _ in $(seq 60); do sleep 10; box test -f /root/READY 2>/dev/null && break; done
    box test -f /root/READY || { echo "cloud-init did not finish; see /var/log/cloud-init-output.log"; exit 1; }
    ip;;
  run) box "cd /root/pqc-scanner2 && nohup bash benchmark/fleet/cloud/suite.sh ${2:?mode} > /root/suite.log 2>&1 < /dev/null & echo started";;
  wait) while ! box test -f /root/SUITE_DONE 2>/dev/null; do sleep 60; done; box tail -5 /root/suite.log;;
  pull) rsh="ssh ${SSH_OPTS[*]}"
        for p in results/ profiles/ LOAD.md; do
          rsync -az -e "$rsh" "root@$(ip):/root/pqc-scanner2/benchmark/fleet/$p" "$REPO/benchmark/fleet/$p"; done;;
  down) doctl compute droplet delete -f "$NAME";;
  *) sed -n 2,9p "$0"; exit 2;;
esac
