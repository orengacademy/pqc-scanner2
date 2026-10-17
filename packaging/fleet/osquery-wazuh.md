# Wazuh and osquery

## Wazuh: command wodle

Wazuh's `command` wodle runs the scan once a day from the Wazuh agent. The wodle runs commands without a
shell, so wrap the call in a small script that loads `/etc/pqcscan/agent.env` (as root) and then runs the scan as the unprivileged `pqcscan` user.

`/usr/local/sbin/pqcscan-report` (root:root, 0750; `/var/lib/pqcscan` owned by `pqcscan`). The `pqcscan` user sees only what it
can read; for a fuller inventory use the systemd unit instead, which grants `CAP_DAC_READ_SEARCH`:

```sh
#!/bin/sh
set -a; . /etc/pqcscan/agent.env; set +a   # PQCSCAN_SERVER, PQCSCAN_LABELS, PQCSCAN_ENROLL_TOKEN (first run)
exec runuser -u pqcscan -- /usr/local/bin/pqcscan scan --fail-on none --report-to "$PQCSCAN_SERVER" --labels="$PQCSCAN_LABELS" \
  --db /var/lib/pqcscan/pqcscan.db --state-dir /var/lib/pqcscan/agent
```

`/var/ossec/etc/ossec.conf` (or the agent group's `agent.conf`):

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>pqcscan-report</tag>
  <command>/usr/local/sbin/pqcscan-report</command>
  <interval>1d</interval>
  <run_on_start>no</run_on_start>
  <ignore_output>yes</ignore_output>
  <timeout>7200</timeout>
</wodle>
```

Install the pinned binary with SHA-256 verification as in `docs/DEPLOYMENT.md` section 1. The first run
enrolls and stores `/var/lib/pqcscan/agent/agent.token`; remove `PQCSCAN_ENROLL_TOKEN` from `agent.env`
and rotate it on the collector after rollout. Add `--ca-cert /etc/pqcscan/ca.pem` for a private CA.

## osquery

osquery is a query engine, not a scheduler: pqcscan is not loaded as an extension. The configuration
management agent (Wazuh, BigFix, Ansible, systemd timer) invokes the binary. osquery is useful only to
watch the agent. This query flags hosts whose last report is stuck in the spool:

```sql
SELECT path, datetime(mtime, 'unixepoch') AS spooled_at
FROM file WHERE path LIKE '/var/lib/pqcscan/agent/spool/%.bundle.gz';
```

The collector's own view (`pqcscan agents list`, the `/fleet` page) remains the source of truth for staleness.
