# Fleet mode — thousands of hosts, one daemon

Fleet mode (phase 1, v0.10.0) lets many hosts report their scan results to one
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
   The `/fleet` page in the web UI is planned for v0.10.1.
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
way and then scans again. The agent keeps its own DB at `<state-dir>/agent.db` and trims it to
`--keep-local` scans (default 3); with a shared `--db` it never prunes.
Other flags: `--once` (one cycle; exit 1 only if the scan crashed, a spooled report exits 0), `--path` (repeatable),
`--db`, `--state-dir`, `--ca-cert`, `--insecure`, `--allow-http`.

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
- **Spool is unbounded for rejected bundles.** A bundle the collector permanently
  rejects stays in the spool directory until you remove it.
- **Postgres is wired but untested.** The URL is accepted and `fleet-pg` installs
  the driver, but the fleet test suite runs on SQLite only.
