# BigFix fixlet: pqcscan fleet agent

Two parts: an install-only Fixlet that puts the pinned binary on the host, and a scan Task that runs one
scan and reports to the fleet daemon. Set the scan Task to Reapply daily (Take Action > Execution > "Reapply an unlimited number of times, wait 1 day between
reapplications"); the install Fixlet is not repeated. Keep the enroll token in
a separate Task that writes `/etc/pqcscan/agent.env`, never in the action text.

## 1. Install Fixlet (binary missing or not the pinned version)

Relevance (verify the inspector name `x64 of operating system` in your BES console, it varies by BigFix version):

```
name of operating system = "Linux" AND x64 of operating system
AND not (exists file "/usr/local/bin/pqcscan"
         AND sha256 of file "/usr/local/bin/pqcscan" = "<SHA-256 of pqcscan-linux-x86_64 from SHA256SUMS.txt>")
```

BigFix `prefetch` needs the size and SHA-1 of the release asset: compute them once with `sha1sum` and
`stat -c %s` on the downloaded `pqcscan-linux-x86_64`. The SHA-256 above comes from the release `SHA256SUMS.txt`.

Action script:

```
prefetch pqcscan-linux-x86_64 sha1:<sha1> size:<bytes> https://github.com/orengacademy/pqc-scanner2/releases/download/v0.10.1/pqcscan-linux-x86_64
wait /usr/bin/install -m 0755 "{pathname of file "pqcscan-linux-x86_64" of folder "__Download"}" /usr/local/bin/pqcscan
```

## 2. Scan Task (Reapply daily)

Relevance:

```
name of operating system = "Linux" AND exists file "/usr/local/bin/pqcscan"
```

Action script:

```
wait /bin/sh -c "set -a; [ -r /etc/pqcscan/agent.env ] && . /etc/pqcscan/agent.env; set +a; exec /usr/local/bin/pqcscan scan --fail-on none --report-to https://pqc.internal:8765 --labels env=prod,group=web --db /var/lib/pqcscan/pqcscan.db --state-dir /var/lib/pqcscan/agent"
```

`/etc/pqcscan/agent.env` (root, mode 0600) holds `PQCSCAN_ENROLL_TOKEN=<token>`. The first run enrolls and stores
`/var/lib/pqcscan/agent/agent.token` (mode 0600); after that the file can be removed; the scan line skips it when it is missing. Rotate the enroll token on the
collector after rollout. For a private CA add `--ca-cert /etc/pqcscan/ca.pem`.

Exit codes: 0 reported or spooled for retry, 2 scan failed.

## Windows

Use `windows-task.ps1` from this directory as the action (`wait powershell.exe -File ...`), or the
Scheduled Task it registers; it verifies the SHA-256 of the pinned binary itself.
