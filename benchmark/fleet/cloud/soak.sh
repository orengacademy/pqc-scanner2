#!/usr/bin/env bash
# Real fleet soak on DigitalOcean: one collector droplet, three Linux agent droplets (soak-real.md).
#   soak.sh up                 # create the four droplets, set up the collector, then every agent; print the server URL
#   soak.sh agent-init <name>  # re-run the agent setup on one agent droplet (after fixing soak-agent-init.sh)
#   soak.sh status             # /api/fleet through the site token: host, os, last_seen, drift
#   soak.sh collect            # sample CSVs, a DB copy, the observer JSON and the redacted collector journal
#   soak.sh down               # destroy the four droplets (they bill until you do)
# Env: DO_REGION=sgp1 DO_SSH_KEY=pqc-campaign PQC_REF=$(git rev-parse HEAD) (must be pushed: the droplets fetch it
#      from GitHub)  PQC_SSH_KEY=<private key path, passed as ssh -i>  PYTHON=<repo venv python, for collect>
# Secrets stay out of the repo: `up` writes them to ~/.config/pqc-soak/env (0600) and prints only the URL.
# shellcheck disable=SC2016,SC2029  # remote commands are built client-side / single-quoted on purpose
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../../.." && pwd)
REGION=${DO_REGION:-sgp1}; KEY=${DO_SSH_KEY:-pqc-campaign}; PY=${PYTHON:-$REPO/.venv/bin/python}
COLLECTOR=pqc-soak-collector
declare -A IMAGE=([pqc-soak-ubuntu]=ubuntu-24-04-x64 [pqc-soak-debian]=debian-12-x64 [pqc-soak-rocky]=rockylinux-9-x64)
AGENTS=(pqc-soak-ubuntu pqc-soak-debian pqc-soak-rocky)
CONF=${XDG_CONFIG_HOME:-$HOME/.config}/pqc-soak; ENV_FILE=$CONF/env
RESULTS=$REPO/benchmark/fleet/results
# DigitalOcean recycles IPs, so each droplet's host key is pinned in its own file: `up` starts them fresh,
# accept-new trusts the first connection, `down` deletes them.
KNOWN=$HERE/.soak_known_hosts
ssh_opts() {
  local o=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$KNOWN/$1" -o LogLevel=ERROR -o BatchMode=yes
           -o ConnectTimeout=10)
  [ -z "${PQC_SSH_KEY:-}" ] || o+=(-i "$PQC_SSH_KEY")
  printf '%s\n' "${o[@]}"
}
# </dev/null: doctl must not eat the stdin that `on` hands to ssh (a tar stream, the enroll token).
ip() { doctl compute droplet list --format Name,PublicIPv4 --no-header </dev/null | awk -v n="$1" '$1==n{print $2}'; }
# Names of the pqc-soak-* droplets that exist. A failed doctl call exits: an empty answer must mean "none".
soak_droplets() {
  local all
  all=$(doctl compute droplet list --format Name --no-header </dev/null) \
    || { echo "doctl compute droplet list failed; cannot tell which soak droplets exist" >&2; exit 1; }
  grep -x 'pqc-soak-.*' <<< "$all" || true
}
host() { local h; h=$(ip "$1"); [ -n "$h" ] || { echo "no droplet named $1" >&2; return 1; }; echo "$h"; }
# on <droplet> <remote command...>: ssh as root with that droplet's pinned host key.
on() { local n=$1 h o; shift; h=$(host "$n") || return 1; mapfile -t o < <(ssh_opts "$n"); ssh "${o[@]}" "root@$h" "$@"; }
# fetch <droplet> <remote path> <local path>
fetch() { local h o; h=$(host "$1") || return 1; mapfile -t o < <(ssh_opts "$1"); scp -q "${o[@]}" "root@$h:$2" "$3"; }
load_env() {
  [ -f "$ENV_FILE" ] || { echo "no $ENV_FILE; run 'soak.sh up' first" >&2; exit 2; }
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  : "${SOAK_SERVER_URL:?}" "${SOAK_SITE_TOKEN:?}" "${SOAK_ENROLL_TOKEN:?}" "${SOAK_CA_PEM_PATH:?}" "${SOAK_REF:?}"
}
still_billing="the soak droplets still exist and bill: inspect them, then run: bash benchmark/fleet/cloud/soak.sh down"
# The CA and the tokens reach an agent only here: the CA by scp, the enroll token on ssh's stdin (never in argv).
agent_init() {
  local name=$1 ref=$2
  local err=none
  for _ in $(seq 30); do err=$(on "$name" true 2>&1) && break; sleep 10; done
  on "$name" true || { echo "$name: no ssh after 5 min (last error: $err); $still_billing" >&2; return 1; }
  git -C "$REPO" archive "$ref" benchmark/fleet/cloud/soak-agent-init.sh benchmark/fleet/cloud/sampler.sh \
      packaging/fleet/pqcscan-agent.service packaging/fleet/pqcscan-agent.timer \
    | on "$name" 'rm -rf /root/soak && mkdir -m 700 /root/soak && tar -x -C /root/soak'
  local h o; h=$(host "$name"); mapfile -t o < <(ssh_opts "$name")
  scp -q "${o[@]}" "$SOAK_CA_PEM_PATH" "root@$h:/root/soak/ca.pem"
  echo "== $name: agent setup at $ref"
  printf '%s\n' "$SOAK_ENROLL_TOKEN" | on "$name" "bash /root/soak/benchmark/fleet/cloud/soak-agent-init.sh '$SOAK_SERVER_URL' $ref" \
    || { echo "$name: agent setup failed (output above); $still_billing" >&2; return 1; }
}
case "${1:-}" in
  up)
    existing=$(soak_droplets)
    [ -z "$existing" ] || { echo "soak droplets already exist: $(echo "$existing" | xargs); run 'soak.sh down' first" >&2; exit 2; }
    REF=$(git -C "$REPO" rev-parse "${PQC_REF:-HEAD}^{commit}")
    [ -n "$(git -C "$REPO" branch -r --contains "$REF")" ] \
      || { echo "$REF is on no remote-tracking branch; push it first (the droplets fetch it from GitHub)" >&2; exit 2; }
    keyid=$(doctl compute ssh-key list --format ID,Name --no-header | awk -v k="$KEY" '$2==k{print $1}')
    [ -n "$keyid" ] || { echo "ssh key $KEY not in DigitalOcean (doctl compute ssh-key import)" >&2; exit 2; }
    # From the first create on, any failing command (agent_init's too: -E) names `down` before set -e exits.
    set -E
    trap 'echo "soak.sh up failed at line $LINENO: $BASH_COMMAND; $still_billing" >&2' ERR
    rm -rf "$KNOWN"; mkdir -p "$KNOWN"
    doctl compute droplet create "$COLLECTOR" --region "$REGION" --size s-2vcpu-4gb --image ubuntu-24-04-x64 \
      --ssh-keys "$keyid" --user-data "$(sed "s|@PQC_REF@|$REF|" "$HERE/soak-collector-init.yaml")" \
      --tag-name pqc-campaign --wait >/dev/null
    for n in "${AGENTS[@]}"; do
      doctl compute droplet create "$n" --region "$REGION" --size s-1vcpu-1gb --image "${IMAGE[$n]}" \
        --ssh-keys "$keyid" --tag-name pqc-campaign --wait >/dev/null
    done
    err=none ready=
    for _ in $(seq 90); do
      sleep 10
      st=$(on "$COLLECTOR" 'if [ -f /root/FAILED ]; then echo "FAILED $(cat /root/FAILED)"; elif [ -f /root/READY ]; then echo "READY $(cat /root/READY)"; fi' 2>&1) || { err=$st; continue; }
      case $st in
        FAILED*) echo "collector cloud-init failed: ${st#FAILED }; see /var/log/cloud-init-output.log on it; $still_billing" >&2; exit 1;;
        READY*) [ "${st#READY }" = "$REF" ] || { echo "collector is at ${st#READY }, wanted $REF; $still_billing" >&2; exit 1; }
                ready=1; break;;
      esac
    done
    [ -n "$ready" ] || { echo "collector cloud-init did not finish in 15 min (last ssh error: $err); $still_billing" >&2; exit 1; }
    (umask 077; mkdir -p "$CONF")
    fetch "$COLLECTOR" /etc/pqcscan/ca.pem "$CONF/ca.pem"
    fetch "$COLLECTOR" /etc/pqcscan/collector.env "$CONF/collector.env"; chmod 600 "$CONF/collector.env"
    site=$(sed -n 's/^PQCSCAN_TOKEN=\([0-9a-f]\{48\}\)$/\1/p' "$CONF/collector.env")
    enroll=$(sed -n 's/^PQCSCAN_ENROLL_TOKEN=\([0-9a-f]\{48\}\)$/\1/p' "$CONF/collector.env")
    [ -n "$site" ] && [ -n "$enroll" ] || { echo "collector.env lacks a 48-hex token pair; $still_billing" >&2; exit 1; }
    (umask 077; printf 'SOAK_SERVER_URL=https://%s:8765\nSOAK_SITE_TOKEN=%s\nSOAK_ENROLL_TOKEN=%s\nSOAK_CA_PEM_PATH=%s\nSOAK_REF=%s\n' \
      "$(host "$COLLECTOR")" "$site" "$enroll" "$CONF/ca.pem" "$REF" > "$ENV_FILE")
    load_env
    for n in "${AGENTS[@]}"; do agent_init "$n" "$REF"; done
    echo "collector: $SOAK_SERVER_URL  (tokens and CA path: $ENV_FILE)";;
  agent-init)
    name=${2:-}
    [ -n "${IMAGE[$name]:-}" ] || { echo "usage: soak.sh agent-init ${AGENTS[*]}" >&2; exit 2; }
    load_env
    agent_init "$name" "$(git -C "$REPO" rev-parse "${PQC_REF:-$SOAK_REF}^{commit}")";;
  status)
    load_env
    curl -fsS --cacert "$SOAK_CA_PEM_PATH" -H @<(printf 'Authorization: Bearer %s\n' "$SOAK_SITE_TOKEN") \
        "$SOAK_SERVER_URL/api/fleet" \
      | "$PY" -c 'import json, sys
rows = json.load(sys.stdin)
print(f"{len(rows)} hosts")
for r in sorted(rows, key=lambda r: r["hostname"] or ""):
    os_ = r["labels"].get("os", r["os"])
    runner = r["labels"].get("runner", "")
    print("%-28s %-8s %-15s last_seen=%s  drift=%s" % (r["hostname"], os_, runner, r["last_seen"], r["drift"]))';;
  collect)
    load_env
    out=$RESULTS/soak-real; day=$(date -u +%Y%m%d); mkdir -p "$out"
    header=$(sed -n 's/^HEADER="\(.*\)"$/\1/p' "$HERE/sampler.sh")
    for n in "$COLLECTOR" "${AGENTS[@]}"; do
      f=$out/${n#pqc-soak-}-samples.csv
      fetch "$n" /var/lib/pqcscan-soak/samples.csv "$f"
      [ "$(head -1 "$f")" = "$header" ] || { echo "$f: first line is not sampler.sh's HEADER" >&2; exit 1; }
      echo "$f: $(($(wc -l < "$f") - 1)) samples"
    done
    # .backup gives a consistent copy of a live WAL database; the copy stays outside the repo.
    db=$CONF/fleet-copy-$day.db
    on "$COLLECTOR" 'sqlite3 /var/lib/pqcscan/fleet.db ".backup /tmp/fleet-copy.db"'
    fetch "$COLLECTOR" /tmp/fleet-copy.db "$db"
    on "$COLLECTOR" 'rm -f /tmp/fleet-copy.db'
    # The journal carries uvicorn's access log, which the observer counts 200/401/403/429/503 from. Tokens are
    # replaced before anything is written into the repo, and the result is checked. The tokens reach sed and grep
    # through process substitution (printf is a builtin), never through argv.
    journal=$CONF/collector-journal-$day.log
    tokens() { printf '%s\n%s\n' "$SOAK_SITE_TOKEN" "$SOAK_ENROLL_TOKEN"; }
    on "$COLLECTOR" 'journalctl -u pqcscan-collector --since -8d -o short-iso --no-pager' \
      | sed -f <(printf 's/%s/<site-token>/g\ns/%s/<enroll-token>/g\n' "$SOAK_SITE_TOKEN" "$SOAK_ENROLL_TOKEN") \
            -e 's/\(Bearer \)[A-Za-z0-9._~+\/=-]*/\1<redacted>/g' > "$journal"
    if grep -qF -f <(tokens) "$journal"; then
      echo "redaction failed: a token is still in $journal" >&2; exit 1
    fi
    gzip -c "$journal" > "$out/collector-journal.log.gz"
    # Run from $CONF with relative names: the JSON records its command line, which must not hold a home directory.
    (cd "$CONF" && PYTHONPATH=$REPO "$PY" -m benchmark.fleet.soak --observe "${db##*/}" --access-log "${journal##*/}" \
      --cycles 1 --interval 0)
    if grep -rqF -f <(tokens) "$out" "$RESULTS"/soak-real-*.json; then
      echo "a token is in a result file under $RESULTS; do not commit" >&2; exit 1
    fi;;
  down)
    existing=$(soak_droplets)
    for n in $existing; do doctl compute droplet delete -f "$n"; done
    [ -n "$existing" ] || echo "no soak droplets to delete"
    # Deletion is asynchronous: a droplet can stay listed for a little while. Wait up to 2 min, then name what is left.
    for _ in $(seq 24); do left=$(soak_droplets); [ -z "$left" ] && break; sleep 5; done
    [ -z "$left" ] || { echo "still listed after delete, and billing: $(echo "$left" | xargs)" >&2; exit 1; }
    rm -rf "$KNOWN"
    echo "droplets gone. The Windows workflow still runs nightly: gh workflow disable soak-windows.yml";;
  *) sed -n 2,9p "$0"; exit 2;;
esac
