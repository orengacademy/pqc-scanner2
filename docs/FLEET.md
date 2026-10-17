# Fleet mode — thousands of hosts, one daemon

Fleet mode (phase 1 in v0.10.0, phase 2 in v0.10.1) lets many hosts report their scan results to one
`pqcscan daemon`. Each host runs a normal one-shot scan and posts the result.
The collector keeps the latest scan per host and builds fleet-wide views and
exports from them.

1. **Collector.** `pqcscan daemon --bind 0.0.0.0 --token <site> --enroll-token <enroll> --tls-cert c.pem --tls-key k.pem`
   (or behind the nginx recipe in [DEPLOYMENT.md](DEPLOYMENT.md) with `--allow-host`).
   Agents authenticate with their own bearer token, so the proxy must not add
   basic auth on `/api/ingest` and `/api/agents/enroll`. The recipe's extra
   `location` block for those two paths does this.
   `--enroll-token` (or `PQCSCAN_ENROLL_TOKEN`) enables `/api/agents/enroll`;
   without it the endpoint is off.
2. **Host, one-shot (recommended).** From cron / systemd timer / Task Scheduler / BigFix / Ansible:
   `pqcscan scan --report-to https://pqc.internal:8765 --enroll-token <enroll> --labels env=prod,group=web --fail-on none`
   The first run enrolls and stores a per-agent token in `<db dir>/agent/agent.token`
   (mode 0600). Later runs reuse it, so the enroll token can be dropped from the
   host after the first run. If the collector is down, the bundle is spooled under
   `<db dir>/agent/spool/` and sent on the next run. Related flags: `--agent-token`,
   `--state-dir`, `--ca-cert` (private CA), `--insecure` (lab only, skips TLS
   verification), `--allow-http` (see Security).
3. **Fleet view.** `GET /api/fleet` (JSON), `pqcscan fleet summary --db …`.
   In the web UI, `/fleet` lists every host with its latest scan, readiness band and crit/high/total counts.
   Hosts not seen for 48 hours are flagged stale. Filter with `/fleet?label=env=prod`; `/fleet/<host_id>` shows one host's scan history.
4. **Exports.** `pqcscan export --scan fleet --format cbom|sarif|xlsx-bukukerja|pdf-tech … -o …`
   builds the export from the latest scan of every host, each finding attributed to its host via `evidence._fleet`.
   The same works from the daemon API: `GET /api/scans/fleet/export/<fmt>`.
5. **Parity (HA/DR).** `pqcscan diff --scan <dr scan> --baseline-scan <primary scan> --fail-on-drift`.
   `pqcscan merge -o fleet.db a.db b.db` still folds per-host DBs offline.
6. **Admin.**
   - `pqcscan agents list` shows every host with `first_seen` and `last_seen` (also in `--json`).
   - `pqcscan agents revoke <id>` blocks a host. `pqcscan agents unrevoke <id>` lets it enroll again:
     its stored token stays invalid, so the agent's next `scan --report-to … --enroll-token …` gets a 401,
     discards `<state dir>/agent.token`, re-enrolls and sends (spooled bundles included). Without
     `--enroll-token` it spools the bundle and tells you to re-run with it or delete the token file.
   - `pqcscan fleet prune --keep 12` keeps the newest 12 scans per host.
7. **Scale.** SQLite handles roughly 2,000 hosts daily. Past roughly 10k per day,
   run the daemon with `--db postgresql+psycopg://user:pw@host/db` (every CLI command
   takes the same `--db` URL; `fleet-pg` installs psycopg 3, so the URL needs
   the `+psycopg` driver suffix) after
   `pip install 'pqcscan[fleet-pg]'`. See Known limits.

## Agent loop (fallback)

Cron or a timer running the one-shot `scan --report-to` stays the recommended mode.
Use the loop only where nothing can schedule a job:

`pqcscan agent --server https://pqc.internal:8765 --enroll-token <enroll> --labels env=prod --interval 24h --jitter 2h`

Each cycle scans, flushes the spool, posts, and spools on failure, with the same token
and re-enroll rules as `scan --report-to`. A spooled report (collector down, 429, 5xx) is not
a failure: the loop retries only the flush, on a backoff from 1 minute capped at 1 hour, and
the next scheduled scan flushes it too. If the scan itself crashes, the agent backs off the same
way and then scans again. A permanent rejection (400, 403, 413) is logged to stderr and the next
scan stays on the normal interval: nothing is spooled and a rescan would be rejected too. The agent keeps its own DB at `<state-dir>/agent.db` and trims it to
`--keep-local` scans (default 3). With any DB other than `<state-dir>/agent.db` it never prunes.
The state dir is created mode 0700. SIGTERM or Ctrl-C stops the loop cleanly (exit 0, "agent: stopping"),
after the cycle in progress finishes. `--interval` must be above zero.
Other flags: `--once` (one cycle; exit 1 if the scan crashed or the collector permanently rejected the report, a spooled report exits 0), `--path` (repeatable),
`--db`, `--state-dir`, `--ca-cert`, `--insecure`, `--allow-http`.

## Deployment recipes

Ready-to-adapt files live in [`packaging/fleet/`](../packaging/fleet/). Each one pins `v0.10.1`, uses https only,
and keeps TLS verification on (use `--ca-cert` for a private CA). The enroll token is needed on the first run only:
rotate it on the collector after rollout.

| File | What it does |
|---|---|
| `pqcscan-agent.service` + `pqcscan-agent.timer` | systemd one-shot `scan --report-to`, daily with up to 2 h random delay. Runs as a dedicated `pqcscan` user with `ProtectSystem=strict`, write access to `/var/lib/pqcscan` only, read-only root access through `CAP_DAC_READ_SEARCH`. Settings come from `/etc/pqcscan/agent.env`. |
| `windows-task.ps1` | Windows PowerShell 5.1 (Desktop edition), not PowerShell 7. Downloads the pinned `.exe` into `%ProgramFiles%\pqcscan` (admin-write only), verifies it against `SHA256SUMS.txt`, creates the state folder `%ProgramData%\pqcscan` fresh and locks it down (SYSTEM and Administrators full, task account modify, verified with `Get-Acl`; it refuses to run over an existing install, so move the old folders aside to upgrade), and registers a daily Scheduled Task (02:00 plus up to 2 h random delay). |
| `ansible-playbook.yml` | Installs the verified binary, the `pqcscan` user, `agent.env` (root:root 0600, enroll token from a vaulted variable, `no_log`) and the timer. Rotate the token after rollout. |
| `bigfix-fixlet.md` | Relevance clause and action script for BigFix. |
| `osquery-wazuh.md` | Wazuh `command` wodle for the daily scan, plus an osquery query that spots a stuck spool. osquery only watches; the CM agent runs the binary. |

The recipes run the one-shot `scan --report-to`, which exits 0 when the report was sent or spooled and 2 when the scan failed.
To get a non-zero exit when the collector permanently rejects a report, change the command to
`pqcscan agent --server "$PQCSCAN_SERVER" --labels "$PQCSCAN_LABELS" --once --db … --state-dir …`
(it reads `PQCSCAN_ENROLL_TOKEN` from the same env file). For a long-running `pqcscan agent` under systemd, use
`Type=simple`, `Restart=on-failure`, `KillSignal=SIGTERM` and `TimeoutStopSec=` longer than a scan.

## Security

- **Enroll token.** Anyone holding `--enroll-token` can enroll any machine id.
  Rotate it after rollout, and review `pqcscan agents list` (`first_seen` /
  `last_seen`) for hosts you do not recognise.
- **No throttling on enrollment.** Guessing the enroll token is not rate limited.
  Use a high-entropy token (for example `openssl rand -hex 32`) and serve TLS.
- **Revoked hosts stay out.** A revoked host cannot re-enroll until you run
  `pqcscan agents unrevoke <id>`.
- **https or loopback.** `--report-to` over plain `http` is refused unless the
  collector host is loopback or you pass `--allow-http`. Agent and enroll tokens
  are bearer credentials, so do not send them in clear text.
- **Tokens hashed at rest.** The collector stores only token hashes. The agent
  keeps its own token in a 0600 file written without following symlinks.
- **Ingest limits.** A bundle is capped at 8 MiB on the wire, 50 MiB after
  decompression and 200,000 findings. Each host may post a burst of 10 bundles,
  refilled at one per minute; only a duplicate resend is free.
  The bundle `machine_id` must match the token that posted it.
- **No key material.** Findings never carry key bytes. Machine ids are
  domain-separated hashes, not raw `/etc/machine-id` values.

## Known limits

- **No split-and-resend on 413.** Bundles are capped when they are dumped on the
  host. A scan larger than the raw cap fails to dump and is not reported.
- **Permanent rejections are not retried.** A bundle the ingest endpoint answers with 400, 403 or
  413 is never spooled; a 400 or 403 at enroll time still spools it. A spooled file that gets one of these moves to `<state dir>/spool/rejected/`
  and flushing continues. Nothing prunes that directory, so clear it by hand. A revoked host's
  reports are dropped this way until you unrevoke it.
- **Postgres is wired but untested.** The URL is accepted and `fleet-pg` installs
  the driver, but the fleet test suite runs on SQLite only.
