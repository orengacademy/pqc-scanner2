# Real fleet soak: runbook

Five real hosts report to one real collector for seven days, on the shipped agent recipe and the shipped binary.
Three are DigitalOcean droplets (Ubuntu, Debian, Rocky) driven by `benchmark/fleet/cloud/soak.sh`. Two are
GitHub-hosted Windows runners driven by `.github/workflows/soak-windows.yml`. The collector runs SQLite.

This is smaller than the 30-host, SQLite-and-Postgres soak the evidence spec describes. It covers what the simulation in
[`SOAK.md`](SOAK.md) cannot: real networks and TLS, systemd timers, real clocks, a real Windows binary, and seven days of
wall time. No faults are injected. Until a dated `results/soak-real-<date>.json` from day 7 exists, every soak claim stays
labelled "simulated".

## What runs where

| Host | Image | Size | Scheduler | Identity |
|---|---|---|---|---|
| `pqc-soak-collector` | `ubuntu-24-04-x64` | `s-2vcpu-4gb` | `pqcscan-collector.service` (systemd, `Restart=on-failure`) | n/a. Serves `https://<public ip>:8765` with a private CA cert for that IP. |
| `pqc-soak-ubuntu` | `ubuntu-24-04-x64` (Python 3.12) | `s-1vcpu-1gb` | shipped `pqcscan-agent.timer`: daily at 00:00 UTC plus up to 2 h random delay | `/etc/machine-id`, stable for the droplet's life |
| `pqc-soak-debian` | `debian-13-x64` (Python 3.13: allowed by `requires-python = ">=3.11"`, but CI tests only 3.11 and 3.12) | `s-1vcpu-1gb` | same timer | `/etc/machine-id` |
| `pqc-soak-rocky` | `rockylinux-9-x64` (Python 3.12 from `dnf`) | `s-1vcpu-1gb` | same timer | `/etc/machine-id` |
| Windows Server 2022 | runner label `windows-2022` | GitHub-hosted | workflow cron 02:00 UTC, then up to 30 min jitter in the job | `MachineGuid` set to `6b1f0c2e-0000-4000-8000-000000002022` before every run. The state dir comes back from the Actions cache. |
| Windows Server 2025 | runner label `windows-latest` (Windows Server 2025 today; GitHub moves this label) | GitHub-hosted | same workflow | `MachineGuid` set to `6b1f0c2e-0000-4000-8000-000000002025`, state dir from the cache |

GitHub-hosted runners do not offer Windows 11. Each runner job is a fresh VM. The workflow makes it the same fleet host every
night in three steps. It pins the registry value pqcscan hashes into the machine id (`src/pqcscan/util/hostid.py`). It restores
`agent.token`, the spool and `agent.db` from the cache. It saves them again after the run, even a failed one. The cache only
ever holds an AES-256 encrypted tarball of the state dir. Any workflow in this public repo can restore the repo's caches,
and the key is the repository secret `SOAK_STATE_KEY`. The job never re-enrols to work around a missing or bad cache. A
tarball that does not decrypt fails the job.

The Linux agents run the shipped `packaging/fleet/pqcscan-agent.service` and `.timer` unchanged. One drop-in,
`pqcscan-agent.service.d/ca.conf`, repeats the shipped `ExecStart` with `--ca-cert /etc/pqcscan/ca.pem` appended, as the unit's
comment says to. Labels are `env=soak,os=<ubuntu|debian|rocky>` on Linux and `env=soak,os=windows,runner=<label>` on Windows.
Every box, collector included, appends one line every 10 minutes to `/var/lib/pqcscan-soak/samples.csv`. The line holds load,
memory, disk, DB and WAL size, state dir size, spool depth, and host, scan and finding counts. The sampler is `cloud/sampler.sh`.

The collector keeps `--keep-scans-per-host 12`, the default.

## What FLEET.md predicts

Each row is checked on day 7. A cell that differs is a finding. Name the host, the day and the log line or drift sample.

| Measure | Prediction | Where it is read | Source |
|---|---|---|---|
| Ingests per host per day | 1 (plus the day-0 run) | `scans` per host in the observer JSON: day 7 holds 8 per host. Same as the `200`s under `statuses.ingest`. | timer `OnCalendar=daily`; `agent --once` is one scan and one report |
| Drift rows per host per day | 0 after day 1 unless the host changed | `drift_rows_newest` per host in each collect, `drift=` in `soak.sh status` | FLEET.md "Drift between scans" |
| 429 | 0 | `statuses.ingest["429"]`, from the collector journal's access log | FLEET.md Security, "Ingest limits": burst 10, one refill a minute, one post a day |
| 503 | 0 | `statuses.ingest["503"]` | same |
| Duplicates | 0 | total ingest `200`s equals total scans stored. A duplicate answers 200 and stores nothing. | FLEET.md Security, "Ingest limits" |
| Prune count | 0 until day 13 | scans per host never drops between collects. 9 scans at most by day 8, under 12 kept. | `--keep-scans-per-host 12` |
| DB growth per host per scan | about 1.2 MB | collector `db_bytes` in `collector-samples.csv`: day 7 minus day 0, divided by scans added | FLEET.md "1.2 MB per scan on one measurement" |
| Token refreshes | 0 | `statuses.enroll["200"]` is 5 for the whole soak, one per host. Any more is a re-enrolment, for example a Windows cache miss. | FLEET.md: a host keeps its agent token |
| Stale flag | none | `last_seen` within 48 h for all five in `soak.sh status`, no stale chip on `/fleet` | FLEET.md "Hosts not seen for 48 hours are flagged stale" |

What counts as "the host changed": unattended package upgrades on the droplets, and a new runner image on Windows. GitHub
updates images about weekly. A drift row on such a day is expected only if it matches that change. On the droplets, check
`/var/log/apt/history.log` or `dnf history`. On Windows, compare the "Runner Image" version printed in the job's setup log.

## Commands

Prerequisites on the operator box:

- `doctl` authenticated, with the SSH key `pqc-campaign` imported (`DO_SSH_KEY` to use another name).
- `PQC_SSH_KEY` pointing at the matching private key, unless ssh finds it by default.
- `gh` authenticated with admin on the repo.
- The repo venv at `.venv`, or `PYTHON=` pointing at a Python with the project installed.
- The commit pushed: the droplets fetch `PQC_REF` from GitHub.
- `soak-windows.yml` on `main`. GitHub runs `schedule` and `workflow_dispatch` only from the default branch's copy. The job
  checks out `SOAK_REF`, so the code under test is still the campaign commit.

```bash
# 1. Collector and Linux agents (about 15 min). Prints only the URL; secrets go to ~/.config/pqc-soak/env (0600).
PQC_REF=$(git rev-parse HEAD) bash benchmark/fleet/cloud/soak.sh up

# 2. Windows: secrets from the env file over stdin, never on a command line; then the day-0 run.
( . ~/.config/pqc-soak/env
  printf %s "$SOAK_SERVER_URL"   | gh secret set SOAK_SERVER_URL
  printf %s "$SOAK_ENROLL_TOKEN" | gh secret set SOAK_ENROLL_TOKEN
  gh secret set SOAK_CA_PEM < "$SOAK_CA_PEM_PATH"
  (umask 077; openssl rand -hex 32 > ~/.config/pqc-soak/state-key)   # encrypts the cached Windows state dir
  gh secret set SOAK_STATE_KEY < ~/.config/pqc-soak/state-key
  gh variable set SOAK_REF --body "$SOAK_REF" )
gh workflow run soak-windows.yml

# 3. Five hosts, last_seen today.
bash benchmark/fleet/cloud/soak.sh status

# 4. Day 0 and day 7 (any day in between is fine too): CSVs, DB copy, observer JSON, redacted journal.
bash benchmark/fleet/cloud/soak.sh collect

# Teardown, see below.
bash benchmark/fleet/cloud/soak.sh down
```

If a Linux agent fails setup, `up` stops and prints the agent's journal. Fix `cloud/soak-agent-init.sh`, not the agent,
unless the agent is at fault, which is a finding. Then push and re-run setup on that droplet alone:
`PQC_REF=<new sha> bash benchmark/fleet/cloud/soak.sh agent-init pqc-soak-rocky`.

`collect` writes the following:

| Path | Content |
|---|---|
| `results/soak-real/<collector\|ubuntu\|debian\|rocky>-samples.csv` | The sampler CSVs. `collect` checks each header against `sampler.sh`. |
| `results/soak-real/collector-journal.log.gz` | `journalctl -u pqcscan-collector --since -8d -o short-iso`. The site token, the enroll token and every `Bearer` value are replaced before it is written. |
| `results/soak-real-<YYYYMMDD>.json` | `python -m benchmark.fleet.soak --observe <DB copy> --access-log <journal> --cycles 1 --interval 0`. It is never overwritten: a second run the same day gets `-2`. |

The DB copy itself is not committed. It is a `sqlite3 .backup` of the live WAL database, kept in `~/.config/pqc-soak/`.
Each JSON is cumulative from day 0, so a later collect's status counts include the earlier days.
`collect` refuses to finish if either token appears in anything it wrote under `results/`. Its `commit` field is the
operator checkout's HEAD. Collect from a checkout at `SOAK_REF`, which the env file records.

## Day 7

1. After 05:00 UTC, run `soak.sh status`. The Linux timers report by about 02:00. The Windows jobs start at 02:00 at the
   earliest, often later, because GitHub delays scheduled runs, and then add up to 30 minutes of jitter. All five hosts
   must show `last_seen` within the last 26 hours. Before counting a missed Windows night, check
   `gh run list --workflow soak-windows.yml` for a late, queued or failed run.
2. Run `soak.sh collect`.
3. Windows exit codes and logs:
   `gh run list --workflow soak-windows.yml --limit 20 --json databaseId,createdAt,conclusion`. Then run
   `gh run download <id> -D benchmark/fleet/results/soak-real/windows/<id>` for each night. Every job should be a
   success. `agent.log` holds the agent's output with the enroll token replaced. `state-listing.txt` shows the spool,
   which should hold no `*.bundle.gz`.
4. Linux hosts, on each droplet, run the following and save the output:

   ```bash
   systemctl show pqcscan-agent.service -p Result -p ExecMainStatus
   journalctl -u pqcscan-agent.service --since -8d -p warning --no-pager
   ls /var/lib/pqcscan/agent/spool
   ```

   `Result=success` and exit 0 are expected, with no warnings and an empty spool. Next to any drift, keep
   `/var/log/apt/history.log` or `dnf history`.
5. Fill the prediction table with an observed column in `benchmark/fleet/SOAK-REAL.md`. Name the commit, the five hosts,
   the dates, and every finding with its evidence. Do not average a non-zero away.
6. Before committing, confirm no secret is in the tree: `grep -rn "$SOAK_ENROLL_TOKEN" benchmark/ docs/` must print
   nothing. Run the same check with `SOAK_SITE_TOKEN`.

## Cost

| Item | Rate | 8 days |
|---|---|---|
| Collector `s-2vcpu-4gb` | $24/month, $0.036/h | about $6.90 |
| Three agents `s-1vcpu-1gb` | $6/month each, $0.009/h | about $5.10 |
| Windows runners | free for a public repo on standard GitHub-hosted runners | $0 |
| Total | | about $12 |

These are DigitalOcean list prices when this was written. Droplets bill until destroyed, powered off or not.

## Teardown

```bash
bash benchmark/fleet/cloud/soak.sh down                 # destroys the four droplets and the pinned host keys
gh workflow disable soak-windows.yml                    # otherwise it runs nightly against a dead collector
gh secret delete SOAK_SERVER_URL; gh secret delete SOAK_ENROLL_TOKEN; gh secret delete SOAK_CA_PEM
gh secret delete SOAK_STATE_KEY
gh variable delete SOAK_REF
gh cache list --key soak-state- --json id --jq '.[].id' | xargs -r -n1 gh cache delete   # encrypted Windows state
rm -rf ~/.config/pqc-soak                               # tokens, state key, CA, DB copies, journals
```

## What this does not test

- **Windows 11.** GitHub-hosted runners offer Windows Server only.
- **IBM i.** There is no IBM i host. The system-values probe is covered only by its unit tests.
- **A persistent Windows disk.** The state dir lives in the Actions cache between runs, not on a disk that stays.
  Unused caches are evicted after 7 days, which is a re-enrolment, not a real host's behaviour.
- **The shipped Windows recipe.** `packaging/fleet/windows-task.ps1` is not used. That means no Scheduled Task, no
  `%ProgramData%` ACLs, no PowerShell 5.1 and no sleep or wake behaviour. The runners run the release-spec binary with the
  same `agent --once` flags.
- **Postgres, 30 hosts, injected faults.** One SQLite collector, five hosts, a healthy week.
- **Losing the state key.** If `SOAK_STATE_KEY` is reset or lost, the cached state cannot be decrypted and the Windows
  jobs fail. The fix is to delete the `soak-state-*` caches, which makes both hosts re-enrol once. That is a token refresh
  to record against the prediction. Keep `~/.config/pqc-soak/state-key` until teardown.
