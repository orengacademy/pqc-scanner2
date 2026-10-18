#!/usr/bin/env bash
# Real soak agent setup, run as root on a fresh Ubuntu 24.04 / Debian 12 / Rocky 9 droplet by `soak.sh up` (or
# `soak.sh agent-init <name>`) over ssh, not cloud-init: Rocky's cloud-init package set differs.
#   bash /root/soak/benchmark/fleet/cloud/soak-agent-init.sh <server url> <commit>   # enroll token on stdin
# soak.sh unpacks `git archive <commit>` of this script, sampler.sh and packaging/fleet/pqcscan-agent.{service,timer}
# under /root/soak and copies the collector's CA to /root/soak/ca.pem first. Safe to re-run on the same droplet.
set -euo pipefail
trap 'echo "agent init failed at line $LINENO: $BASH_COMMAND" >&2' ERR
server=${1:?usage: soak-agent-init.sh <server url> <commit>}
ref=${2:?usage: soak-agent-init.sh <server url> <commit>}
IFS= read -r enroll
[[ $enroll =~ ^[0-9a-f]{48}$ ]] || { echo "the enroll token on stdin is not 48 hex characters" >&2; exit 2; }
SRC=/root/soak

# The image's own first-boot cloud-init may still be installing packages; let it finish first.
cloud-init status --wait >/dev/null || echo "cloud-init finished with exit $? (continuing)" >&2
# shellcheck source=/dev/null
. /etc/os-release
case $ID in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    # apt-daily / unattended-upgrades hold the dpkg lock for a while after first boot: wait instead of failing.
    apt-get -o DPkg::Lock::Timeout=900 update -q
    apt-get -o DPkg::Lock::Timeout=900 install -y -q python3-venv git cron
    py=python3 nologin=/usr/sbin/nologin crond=cron;;
  rocky)
    dnf install -y -q python3.12 git cronie
    py=python3.12 nologin=/sbin/nologin crond=crond;;
  *) echo "unsupported distro: $ID" >&2; exit 2;;
esac
"$py" -c 'import sys; assert sys.version_info >= (3, 11), sys.version'
"$py" -m venv /opt/pqcscan
# pip counts an unchanged requirement name as installed, so a re-run at a new sha would keep the old code: force the
# package itself, then let a plain install add whatever dependencies that sha needs (all of them on the first run).
pkg="git+https://github.com/orengacademy/pqc-scanner2@$ref"
/opt/pqcscan/bin/pip install -q --force-reinstall --no-deps "$pkg"
/opt/pqcscan/bin/pip install -q "$pkg"
ln -sfn /opt/pqcscan/bin/pqcscan /usr/local/bin/pqcscan
pqcscan version

# The user exactly as the shipped unit's comment says; it must also create the pqcscan group the unit runs under.
id -u pqcscan >/dev/null 2>&1 || useradd --system --home-dir /var/lib/pqcscan --shell "$nologin" pqcscan
getent group pqcscan >/dev/null || { echo "useradd made no pqcscan group; the unit's Group=pqcscan will fail" >&2; exit 1; }
install -d -m 0755 /etc/pqcscan
install -m 0644 "$SRC/ca.pem" /etc/pqcscan/ca.pem
# The token stays after the first report (unit comment: optional once enrolled); the soak leaves it in place.
(umask 077; printf 'PQCSCAN_SERVER=%s\nPQCSCAN_LABELS=env=soak,os=%s\nPQCSCAN_ENROLL_TOKEN=%s\n' \
  "$server" "$ID" "$enroll" > /etc/pqcscan/agent.env)

# Shipped units verbatim; the CA goes in a drop-in that repeats the shipped ExecStart plus --ca-cert (FLEET.md).
install -m 0644 "$SRC/packaging/fleet/pqcscan-agent.service" "$SRC/packaging/fleet/pqcscan-agent.timer" \
  /etc/systemd/system/
exec_start=$(grep '^ExecStart=' /etc/systemd/system/pqcscan-agent.service)
[ "$(printf '%s\n' "$exec_start" | wc -l)" = 1 ] || { echo "expected one ExecStart= in the shipped unit" >&2; exit 1; }
install -d -m 0755 /etc/systemd/system/pqcscan-agent.service.d
printf '[Service]\nExecStart=\n%s --ca-cert /etc/pqcscan/ca.pem\n' "$exec_start" \
  > /etc/systemd/system/pqcscan-agent.service.d/ca.conf
systemctl daemon-reload
systemctl enable --now pqcscan-agent.timer
# Day-0 run. A oneshot start blocks until the scan and the report finish and fails if the agent exited non-zero.
if ! systemctl start pqcscan-agent.service; then
  journalctl -u pqcscan-agent.service -n 60 --no-pager >&2
  exit 1
fi
systemctl show pqcscan-agent.service -p Result -p ExecMainStatus

install -m 0755 "$SRC/benchmark/fleet/cloud/sampler.sh" /usr/local/sbin/pqc-soak-sampler
install -d -m 0755 /var/lib/pqcscan-soak
echo '*/10 * * * * root /usr/local/sbin/pqc-soak-sampler agent 2>>/var/lib/pqcscan-soak/sampler.err' \
  > /etc/cron.d/pqc-soak-sampler
systemctl enable --now "$crond"
/usr/local/sbin/pqc-soak-sampler agent
echo "agent ready at $ref"
