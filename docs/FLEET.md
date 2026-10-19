# Fleet mode — thousands of hosts, one daemon

Fleet mode (phase 1 in v0.10.0, phase 2 in v0.10.1, phase 3 in v0.10.2) lets many hosts report their scan results to one
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
2. **Host, one-shot.** For ad-hoc and CI runs. For scheduled jobs use `pqcscan agent --once` (see Deployment recipes), which also prunes its local DB:
   `pqcscan scan --report-to https://pqc.internal:8765 --enroll-token <enroll> --labels env=prod,group=web --fail-on none`
   The first run enrolls and stores a per-agent token in `<db dir>/agent/agent.token`
   (mode 0600). Later runs reuse it, so the enroll token can be dropped from the
   host after the first run. If the collector is down, the bundle is spooled under
   `<db dir>/agent/spool/` and sent on the next run. Related flags: `--agent-token`,
   `--state-dir`, `--ca-cert` (private CA), `--insecure` (lab only, skips TLS
   verification), `--allow-http` (see Security).
3. **Fleet view.** `GET /api/fleet` (JSON), `pqcscan fleet summary --db …`.
   In the web UI, `/fleet` lists every host with its latest scan, readiness band and crit/high/total counts.
   A `drift N` chip marks a host whose latest scan changed since the one before (also `drift` in the JSON);
   `/fleet/<host_id>` shows the same count per scan.
   Hosts not seen for 48 hours are flagged stale. Filter with `/fleet?label=env=prod`; `/fleet/<host_id>` shows one host's scan history.
   Host labels `data_lifetime`, `migration_years` and `threat_years` (all in years) set the Mosca X, Y and Z inputs in that host's reports; without them the defaults apply, and invalid labels are ignored.
   Labels merge, so one the agent stops sending stays on the host. To drop it, have the agent send an invalid value
   (for example `--labels data_lifetime=unset`) and the report falls back to the defaults.

   **Crypto-agility score.** Reports also carry a 0 to 100 crypto-agility score: how cheaply the quantum-vulnerable
   findings' cryptography can be changed (edit a config scores 90, rebuild or replace hardware scores 10). It is the
   mean per-finding score and is shown in the executive and technical PDFs, the JSON report context, and the
   BUKUKERJA CBOM sheet (per finding). Bands: `high` at 70 or more, `medium` at 40 or more, otherwise `low`.
   Informational and `fleet.drift` findings are ignored; a scan with nothing vulnerable scores 100.
   The fleet export's score is the same mean over every host's findings, so it is weighted by finding count:
   hosts with many findings dominate it.
4. **Exports.** `pqcscan export --scan fleet --format cbom|sarif|xlsx-bukukerja|pdf-tech … -o …`
   builds the export from the latest scan of every host, each finding attributed to its host via `evidence._fleet`.
   The same works from the daemon API: `GET /api/scans/fleet/export/<fmt>`.
5. **Parity (HA/DR).** `pqcscan diff --scan <dr scan> --baseline-scan <primary scan> --parity --fail-on-drift`.
   `pqcscan merge -o fleet.db a.db b.db` still folds per-host DBs offline.
6. **Admin.**
   - `pqcscan agents list` shows every host with `first_seen` and `last_seen` (also in `--json`).
   - `pqcscan agents revoke <id>` blocks a host. `pqcscan agents unrevoke <id>` lets it enroll again:
     its stored token stays invalid, so the agent's next `scan --report-to … --enroll-token …` gets a 401,
     discards `<state dir>/agent.token`, re-enrolls and sends (spooled bundles included). Without
     `--enroll-token` it spools the bundle and tells you to re-run with it or delete the token file.
   - `pqcscan fleet prune --keep 12` keeps the newest 12 scans per host. It is for one-off trims: the daemon already does this after every ingest (see Retention).
7. **Scale.** SQLite handles roughly 2,000 hosts daily with margin. On an 8-vCPU droplet with real-size
   (1,670-finding) bundles it sustains 1 post/s at p95 under 2 s, about 7,200 hosts on the daily timer with its 2 h
   jitter, and 2,000 hosts offer 0.28 posts/s (see Known limits, Ingest capacity). At the default 12 scans per host the
   database reaches about 28 GB for 2,000 hosts (1.2 MB per scan on one measurement; the real soak re-measures it).
   SQLite is also the faster backend on that box. Postgres works, for operators who need it for other reasons: run the
   daemon with `--db postgresql+psycopg://user:pw@host/db` (every CLI command takes the same `--db` URL; `fleet-pg`
   installs psycopg 3, so the URL needs the `+psycopg` driver suffix) after `pip install 'pqcscan[fleet-pg]'`. Its
   measured cost: on the same box it did not reach p95 under 2 s at any swept rate, 0.5 posts/s and up, because it pays
   one insert and one foreign-key check per finding row. See Known limits and [FLEET-EVIDENCE.md](FLEET-EVIDENCE.md).

## Retention

After each stored bundle the daemon deletes that host's scans beyond the newest 12 (by server scan id), so the
database stops growing without a cron job. Change the number with `pqcscan daemon --keep-scans-per-host N`
(or `PQCSCAN_KEEP_SCANS_PER_HOST`); the minimum is 2, there is no off switch. The scan just ingested is never
removed, other hosts are untouched, and a duplicate bundle prunes nothing. If the trim itself fails the ingest
still succeeds and a warning is logged. The agent's own `--keep-local` is a separate, client-side setting.
Scans saved as a baseline are never pruned and do not count toward N, so a host keeps N other scans plus its baselines.
Failed and interrupted scans count toward N, but the host's newest completed scan is always kept.

## Agent loop (fallback)

Cron or a timer running `pqcscan agent --once` (see Deployment recipes) stays the recommended mode.
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

Ready-to-adapt files live in [`packaging/fleet/`](../packaging/fleet/). Each one pins `v0.10.2`, uses https only,
and keeps TLS verification on (use `--ca-cert` for a private CA). The enroll token is needed on the first run only:
rotate it on the collector after rollout.

| File | What it does |
|---|---|
| `pqcscan-agent.service` + `pqcscan-agent.timer` | systemd one-shot `agent --once`, daily with up to 2 h random delay. Runs as a dedicated `pqcscan` user with `ProtectSystem=strict`, write access to the state dir `/var/lib/pqcscan/agent` only, read-only root access through `CAP_DAC_READ_SEARCH`. Settings come from `/etc/pqcscan/agent.env`. |
| `windows-task.ps1` | Windows PowerShell 5.1 (Desktop edition), not PowerShell 7. Downloads the pinned `.exe` into `%ProgramFiles%\pqcscan` (admin-write only), verifies it against `SHA256SUMS.txt`, creates the state folder `%ProgramData%\pqcscan` fresh and locks it down (SYSTEM and Administrators full, task account modify, verified with `Get-Acl`; it refuses to run over an existing install, so to upgrade or rotate the token stop the task and move both folders aside, which drops the spool and `agent.token` and makes the host re-enroll), and registers a daily Scheduled Task (02:00 plus up to 2 h random delay). `-RunAs` accepts `NT AUTHORITY\SYSTEM` (the default) or a group managed service account (`DOMAIN\name$`, which CI cannot exercise) and refuses anything else before it writes anything: `LOCAL SERVICE`, `NETWORK SERVICE` and other shared accounts because every service running as them could read the token in `agent.env`, a plain user because it needs a password the script does not take, `NT SERVICE\` virtual accounts because this installer does not support them; an account that passes that check but that Task Scheduler rejects (a gMSA this host cannot use, or a computer account) fails at registration and the installer removes what it wrote. |
| `ansible-playbook.yml` | Installs the verified binary, the `pqcscan` user, `agent.env` (root:root 0600, enroll token from a vaulted variable, `no_log`) and the timer. Rotate the token after rollout. |
| `bigfix-fixlet.md` | Relevance clause and action script for BigFix. |
| `osquery-wazuh.md` | Wazuh `command` wodle for the daily scan, plus an osquery query that spots a stuck spool. osquery only watches; the CM agent runs the binary. |

The recipes run `pqcscan agent --once`: one scan, report, then a trim of the agent's own local database
(`<state-dir>/agent.db`, newest `--keep-local` scans, default 3). It exits 0 when the report was sent or spooled for retry
and 1 when the scan crashed or the collector permanently rejected the report, so the timer or task records the failure.
`scan --report-to` stays for ad-hoc and CI runs: it never prunes the database it scans into, so a daily cron of it grows
that database by one scan a day. For a long-running `pqcscan agent` under systemd, use `Type=simple`,
`Restart=on-failure`, `KillSignal=SIGTERM` and `TimeoutStopSec=` longer than a scan.

**Rotating the enrollment token.** Restart the daemon with a new `--enroll-token` (or `PQCSCAN_ENROLL_TOKEN`).
Hosts that already enrolled keep working, because they use their own agent token. Only new or re-enrolling hosts need the new value.

**`machine_id` mismatch (403).** The ingest endpoint refuses a bundle whose machine id does not match the agent token, for example
after a cloned VM image. Delete `<state-dir>/agent.token` on that host and run it again with `--enroll-token`.
Bundles already in the spool that get the 403 move to `<state-dir>/spool/rejected/`. A bundle the host has just scanned and sent is not kept, so the next scan after re-enrolling reports instead.

## Drift between scans

When a host's bundle is ingested, the collector compares it with that host's previous completed scan.
Each finding that appeared or vanished becomes one `fleet.drift` finding (severity info) in the new scan,
with `evidence.change` set to `added` or `removed`. The first scan of a host, and any failed or interrupted
scan, produces none. Drift rows are left out of the fleet counts and of the fleet rollup. The ingest response
reports the number of changes as `drift`. At most 500 change rows are stored per scan; beyond that one summary row
(`evidence.change` = `summary`) carries the full added and removed counts. When the two scans hold more than
50,000 findings together, only the summary row is stored and changes are counted on the raw title.

Findings are matched by a host-agnostic key, so host names, addresses and `at <host>` phrases do not count
as change. `pqcscan diff --parity` uses the same key to compare a primary with its DR peer, and with
`--fail-on-drift` it exits 1 only on real differences.

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
  refilled at one per minute. Every post spends a token before the bundle is read, a duplicate resend included: it is
  answered `200` with `duplicate: true`, and after 10 in a row the next one gets `429`.
  Host labels are capped at 64 per host, keys at 64 characters and values at 256, at enrollment and ingest.
  Labels merge across bundles. At 64 the host keeps its labels, existing keys take their new values, new keys are
  dropped (in sorted order) and the collector logs one warning naming them; the scan is still stored. There is no command to delete a label.
  The bundle `machine_id` must match the token that posted it.
  The collector parses and stores two bundles at a time and holds at most 32 bundles in all, those being parsed
  included; past that it answers `503` with `Retry-After: 60`, before reading the body when it is already full, and
  the agent spools the bundle and sends it on its next run. At most 64 uploads are read at once, with the same `503`
  past that; a body must arrive within 120 s (`408` otherwise, which the agent also retries), and one host may have
  two uploads in flight.
  A bundle takes its place in the queue only once its body is fully read, so a slow upload holds none. The queue is
  sized so a bundle waits about half a minute at 2 s per bundle, inside the agent's 60 s timeout. When 500 hosts post
  at once a few requests still go unanswered within 60 s (6 of 1,497 on SQLite, 14 of 1,486 on Postgres, on the load
  box); the agent spools those and sends them on its next run.
- **No key material.** Findings never carry key bytes. Machine ids are
  domain-separated hashes, not raw `/etc/machine-id` values.

## Known limits

- **No split-and-resend on 413.** Bundles are capped when they are dumped on the
  host. A scan larger than the raw cap fails to dump and is not reported.
- **Permanent rejections are not retried.** A bundle the ingest endpoint answers with 400, 403 or
  413 is never spooled; a 400 or 403 at enroll time still spools it. A spooled file that gets one of these moves to `<state dir>/spool/rejected/`
  and flushing continues. Nothing prunes that directory, so clear it by hand. A revoked host's
  ingest gets 401 and its re-enroll gets 403, so its bundles spool and replay after `agents unrevoke`.
  Replaying needs the enrollment token on the host again (`--enroll-token` / `PQCSCAN_ENROLL_TOKEN`) if it was removed after the first run.
- **Ingest capacity.** Measured on an 8-vCPU DigitalOcean droplet (`benchmark/fleet/CAPACITY.md`, CPU model
  `DO-Regular`, shared cores), with 1,670-finding bundles and p95 under 2 s, SQLite sustains λ_max = 1 post/s (band 1 to
  2). Under the daily timer with a 2 h jitter that is about 7,200 hosts, or 86,400 if the posts are spread over 24 h.
  Postgres met p95 < 2 s at no swept rate: at the lowest, 0.5 posts/s, p95 was 2.2 to 2.3 s, and the sweep did not go
  lower. FLEET.md's 2,000 hosts offer 0.28 posts/s, inside the SQLite figure with margin. A herd of 500 hosts at once gets
  1,186 `503`s on SQLite and 1,272 on Postgres, and 6 and 14 ingests that were never answered (finding F24); p95 stays
  at 15 s and 27 s, below the agent's 60 s timeout. These figures are for this box class: the GitHub `ubuntu-latest`
  runner measured p95 150 ms (SQLite) and 710 ms (Postgres) at 1 post/s, about five times faster on SQLite (4.9 to 5.1
  times) and six on Postgres (5.8 to 6.6 times), at 60 hosts on the runner against 100 on the box. History: the PR #92
  rows (`benchmark/fleet/LOAD-pr92.md`) ran at 8.3 posts/s, 30 times FLEET.md's 2,000-host rate. See
  `benchmark/fleet/CAPACITY.md` and [FLEET-EVIDENCE.md](FLEET-EVIDENCE.md).
- **Postgres is tested in CI and profiled.** The URL is accepted, `fleet-pg` installs the driver, and the CI job
  `postgres` (`.github/workflows/verify.yml`) runs 120 fleet tests against `postgres:16-alpine`. Under the load test
  it was no faster than SQLite, and on the 8-vCPU `DO-Regular` droplet it does not reach p95 < 2 s with 1,670-finding
  bundles at any swept rate, while the CI runner does at 1 post/s (p95 710 ms). Profiled before and after
  (`benchmark/fleet/profiles/postgres-before`, `postgres-after`): statements per ingest went from 16,996 to 16,103,
  time inside psycopg's `wait` from 66.4 % to 68.8 % of sampled wall time, and `_communicate_gen` (the psycopg
  pipeline: one server execution and one FK check per inserted row) from 28.1 % to 26.8 % self. SQLite stores findings
  as multi-row `INSERT ... VALUES` pages and Postgres keeps psycopg's pipelined one-row-per-execution inserts: on the
  load box Postgres reached the same rate either way, bound by its per-row FK checks, with lower latency pipelined
  (`benchmark/fleet/results/load-postgres-20261018-r4-pginsert*.json`). Four ingest slots instead of two were measured
  slower on Postgres (p95 48 s with four against 29 s with two at 4 posts/s on the box, 1.5 to 2.2 times the baseline
  p95 in CI, and 7.5 to 8.8 s against 2.2 to 2.3 s at 0.5 posts/s), so it parses two bundles at a time like SQLite. The
  per-row cost is finding F23 in `benchmark/fleet/CAPACITY.md` and [FLEET-EVIDENCE.md](FLEET-EVIDENCE.md); bulk loading with `COPY` or batched inserts and deferred FK checks is the proposed
  fix and is not done.
