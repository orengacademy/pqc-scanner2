# BigFix fixlet: pqcscan fleet agent

Deploys the pinned binary and runs one scan that reports to the fleet daemon. Create a Fixlet
(or Task) with the relevance and action script below, then target it at the hosts and set the action to
repeat daily (Take Action > Schedule > Reapply, interval 1 day). Keep the enroll token in a BigFix
encrypted property or a separate agent.env deployed with restricted file ACLs, never in the action text.

## Relevance (Linux x86_64 host where the pinned binary is missing or different)

```
name of operating system = "Linux" AND x86_64 of operating system
AND not (exists file "/usr/local/bin/pqcscan"
         AND sha256 of file "/usr/local/bin/pqcscan" = "<SHA-256 of pqcscan-linux-x86_64 from SHA256SUMS.txt>")
```

## Action script (Linux)

BigFix `prefetch` needs the size and SHA-1 of the release asset: compute them once with `sha1sum` and
`stat -c %s` on the downloaded `pqcscan-linux-x86_64`. The SHA-256 above comes from the release `SHA256SUMS.txt`.

```
prefetch pqcscan-linux-x86_64 sha1:<sha1> size:<bytes> https://github.com/orengacademy/pqc-scanner2/releases/download/v0.10.1/pqcscan-linux-x86_64
wait install -m 0755 "{pathname of file "pqcscan-linux-x86_64" of folder "__Download"}" /usr/local/bin/pqcscan
wait /bin/sh -c "set -a; . /etc/pqcscan/agent.env; set +a; exec /usr/local/bin/pqcscan scan --fail-on none --report-to https://pqc.internal:8765 --labels env=prod,group=web --db /var/lib/pqcscan/pqcscan.db --state-dir /var/lib/pqcscan/agent"
```

`/etc/pqcscan/agent.env` (root, mode 0600) holds `PQCSCAN_ENROLL_TOKEN=<token>`, deployed by a separate
Task so the token is not in the action text. The first run enrolls and stores
`/var/lib/pqcscan/agent/agent.token` (mode 0600); after that the file can be removed. Rotate the enroll token on the
collector after rollout. For a private CA add `--ca-cert /etc/pqcscan/ca.pem`.

Exit codes: 0 reported or spooled for retry, 2 scan failed.

## Windows

Use `windows-task.ps1` from this directory as the action (`wait powershell.exe -File ...`), or the
Scheduled Task it registers; it verifies the SHA-256 of the pinned binary itself.
