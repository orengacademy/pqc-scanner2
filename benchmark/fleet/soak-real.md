# Real fleet soak: runbook (NOT YET RUN)

This is the procedure for the real soak: at least 30 real or VM hosts, seven daily cycles, on SQLite and again on
Postgres. It has not been run. The only soak result so far is the simulation in [`SOAK.md`](SOAK.md), which ran on
one box with minute-scale cycles. A pass there says the code paths behave as `docs/FLEET.md` describes. It says nothing
about real networks, real clocks, Windows, systemd timers or seven days of wall time.

The collector side uses the same script as the simulation (`python -m benchmark.fleet.soak --observe`), so the real
numbers have the same columns as the simulated ones and can be put next to them.

## What you need

| Item | Detail |
|---|---|
| Hosts | 30 or more. Suggested mix: 15 Linux, 14 Windows, plus the IBM i export below. All must reach the collector over https (or loopback http for a lab). |
| Collector box | Any Linux box that can run `pqcscan daemon`. Keep its clock on NTP. Postgres run: a Postgres 16 server and `pip install 'pqcscan[fleet-pg]'`. |
| Operator box | Can run `pqcscan agents revoke|unrevoke` against the collector DB and read the collector's log. Usually the collector box. |
| Repo checkout | `pip install -e '.[dev]'` on the collector box, for `benchmark.fleet.soak`. The checkout must be at the commit you are testing. Record `git rev-parse HEAD`. |
| Time | Day 0 for rollout, then seven daily cycles (days 1 to 7), then half a day to collect. |

## 1. Start the collector (once per database)

Run it the way production would, with its stderr kept in a file. Add `--allow-host <the DNS name the agents use>`
(for example `--allow-host pqc.internal`, repeatable). The daemon answers 400 to any request whose Host header is not
loopback, the bind address or the machine's own hostname, so without it every agent that reaches the collector by an
alias fails to enrol (`daemon/app.py`, the DNS-rebinding guard). The uvicorn access log in that file is the source of
the 429 and 503 counts.

```bash
# SQLite
pqcscan daemon --bind 0.0.0.0 --allow-host pqc.internal --token "$SITE" --enroll-token "$ENROLL" \
    --tls-cert c.pem --tls-key k.pem --db /var/lib/pqcscan/fleet.db --keep-scans-per-host 12 2>&1 | tee -a /var/log/pqcscan/collector-sqlite.log

# Postgres (a separate run, see section 6)
pqcscan daemon --allow-host pqc.internal ... --db postgresql+psycopg://pqc:***@db.internal/pqc 2>&1 | tee -a /var/log/pqcscan/collector-pg.log
```

Leave `--keep-scans-per-host` at the default 12 for the real run. The simulation used 3 so that pruning shows up in
a few cycles. With daily scans and 12 kept, retention first prunes on day 13, so a seven day soak will read **0 pruned**
unless you lower it. Either state that 0 is the expected value, or run with `--keep-scans-per-host 3` to see pruning
(the minimum is 2) and say so in the report.

## 2. Enrol the hosts with the shipped recipes, unmodified

Do not hand-roll the schedule. The point is to exercise the recipes as shipped.

| Host type | Recipe | Notes |
|---|---|---|
| Linux | `packaging/fleet/ansible-playbook.yml` (or `pqcscan-agent.service` + `.timer` by hand) | Timer runs daily with up to 2 h random delay. State dir `/var/lib/pqcscan/agent`. |
| Windows | `packaging/fleet/windows-task.ps1` in Windows PowerShell 5.1, elevated, with `-Server` and `-EnrollToken` | Registers the task `pqcscan-agent` (daily 02:00 plus up to 2 h random delay). State dir `%ProgramData%\pqcscan\agent`. Run the script as shipped; do not edit it. |
| Other CM tools | `bigfix-fixlet.md`, `osquery-wazuh.md` | Use the same labels. |
| IBM i export | Not an agent host. | The `fs.conf.ibmi_sysval` probe reads an exported system-values file. Put the export in a directory on one enrolled Linux host and scan it by adding `--path <dir>` to that host's `ExecStart`. That is the one allowed change to a recipe, and it makes the host report the export's findings. Record it. |

Give every host the same three labels the simulation used, so the label count column is comparable:
`group=...`, `site=...`, `env=soak`. Run each recipe's first scan by hand on day 0
(`systemctl start pqcscan-agent.service`, or `Start-ScheduledTask -TaskName pqcscan-agent`) and confirm
`pqcscan agents list` shows all 30 hosts before starting the clock.

## 3. Start the observer (day 0, after the hosts have enrolled)

On the collector box, in `tmux` or under `nohup`, so it survives a logout for seven days:

```bash
python -m benchmark.fleet.soak --observe /var/lib/pqcscan/fleet.db \
    --access-log /var/log/pqcscan/collector-sqlite.log --cycles 7 --interval 86400
# Postgres: --observe 'postgresql+psycopg://pqc:***@db.internal/pqc'
```

Every 86,400 s it writes one snapshot, then at the end `benchmark/fleet/results/soak-real-<YYYYMMDD>.json` (never
overwritten). Per cycle and host it records scans stored, label count, scans added since the last snapshot, older scans
that retention removed, and the drift rows on the host's newest scan, with a sample of their text. Per cycle it records
the ingest and enrol status counts from the access log (200, 401, 403, 429, 503 and anything else).

Start the access log at the same moment, so day 1 does not count the rollout. If the log already has history, start
a fresh file for the soak.

The observer is read-only: it opens SQLite with `mode=ro` and Postgres with `default_transaction_read_only`, runs only
SELECTs and never creates or migrates a table. It has one automated test (a database missing a column is left
unchanged) and has not been run against a real fleet.

Limits of the observer: it sees the collector only. It cannot count a bundle that was ingested and pruned within the
same 24 h (more than the retention number in a day), and it cannot tell a duplicate (200 with `duplicate: true`)
from a normal 200. Section 5 covers duplicates.

## 4. Collect on the hosts, every day

Spool depth, rejected files and the agent's exit code exist only on the host. Collect them once a day, after the
timer window (about 04:30 local) with your CM tool, into one CSV `host,day,exit,spool,rejected`.

Linux:

```bash
systemctl show pqcscan-agent.service -p Result -p ExecMainStatus      # exit 0 expected; Result=success
ls /var/lib/pqcscan/agent/spool/*.bundle.gz 2>/dev/null | wc -l        # spool depth
ls /var/lib/pqcscan/agent/spool/rejected 2>/dev/null | wc -l           # rejected files
journalctl -u pqcscan-agent.service --since yesterday -p warning       # spool and re-enrol warnings
```

Windows (PowerShell 5.1):

```powershell
(Get-ScheduledTaskInfo -TaskName pqcscan-agent).LastTaskResult                          # 0 expected
(Get-ChildItem "$env:ProgramData\pqcscan\agent\spool\*.bundle.gz" -ErrorAction SilentlyContinue).Count
(Get-ChildItem "$env:ProgramData\pqcscan\agent\spool\rejected" -ErrorAction SilentlyContinue).Count
```

Also keep: the collector log file (the whole of it), `pqcscan agents list --json` at the end, and the size of the DB
file (or `pg_database_size`).

## 5. Inject the same faults as the simulation

Optional, but without them a healthy week proves little. Times are relative to the day-N timer window. Use the
same host picks if you can (the 5th, 7th and 9th enrolled).

| Day | Fault | How | Expected (FLEET.md) |
|---|---|---|---|
| 2 | Collector down for the whole day | Stop the daemon after the day-1 collection, start it again before day 3's window | Every host exits 0 with one bundle spooled; day 3 spool back to 0 and two bundles stored per host |
| 3 (after the window) | Revoke one host | `pqcscan agents revoke <id> --db ...` | From day 4: its ingest gets 401, its re-enroll 403, the bundle spools, exit 0 |
| 4 | One host's scanned content changes | Drop a different cert file into a directory that host scans (a copy of a cert with a changed subject) | Drift above 0 on that host's day-4 scan, 0 on day 5 |
| 5 (after the window) | Unrevoke | `pqcscan agents unrevoke <id> --db ...` | Day 6: it enrols, the spooled bundles replay, spool 0 |
| 6 (after the window) | Re-post a bundle that was already stored | See below | `200` with `duplicate: true`, no new scan |

To re-post a stored bundle, rebuild it from the host's own agent DB. The agent keeps the newest three local scans.
Run this on that host as the agent user, with the host's token:

```bash
python - <<'EOF'
import socket, httpx
from pathlib import Path
from pqcscan import __version__
from pqcscan.store.bundle import HostIdentity, dump_bundle
from pqcscan.store.repo import Repo
from pqcscan.util.hostid import machine_id
state = Path("/var/lib/pqcscan/agent")
repo = Repo(state / "agent.db")
older = repo.list_scans()[1]                    # the previous scan, already stored by the collector
ident = HostIdentity(machine_id=machine_id(), hostname=socket.gethostname(), os="linux",
                     labels={"env": "soak"}, agent_version=__version__)
r = httpx.post("https://pqc.internal:8765/api/ingest", content=dump_bundle(repo, older.id, ident),
               headers={"authorization": "Bearer " + (state / "agent.token").read_text().strip(),
                        "content-type": "application/gzip"})
print(r.status_code, r.json())
EOF
```

A duplicate resend costs a token like any other post (`docs/FLEET.md`, Ingest limits). The expected shape on a host with
a full bucket is ten answers of `200` with `duplicate: true`, then `429`. To check, re-post the bundle until a 429
appears and count the 200s; far more than 10, or no 429 at all, would be a finding. Do this after the last cycle,
because it empties that host's bucket for a minute. The snippet is Linux-only (state dir and `os="linux"` are hard-coded).

## 6. Both databases

The spec asks for SQLite and, separately, Postgres. A host reports to one collector at a time, so either:

1. run the whole soak twice, one week each, re-pointing the hosts for the second week (stop the task, move the state
   dir aside as the Windows script header says, change the server in `agent.env`); or
2. split the fleet: 30 or more hosts on each collector.

Do not point the same host at both in one week: its spool and token would be shared.

## 7. Compare with the simulation

1. Run `python -m benchmark.fleet.soak --render results/soak-simulated-<db>-<date>.json` to print the simulated
   tables. The real observer's per-cycle line has the same measures. The rest come from your host CSV.
2. Fill this table for each database. Expected values are the ones in the right-hand column. A cell that differs
   is a finding, with the sentence in `docs/FLEET.md` that it contradicts, or "FLEET.md is silent".

Pass or fail. The soak **fails** if any of these is true on a healthy day (outside an injected fault): a 429 or a 503;
an agent exit code other than 0; a file in any `spool/rejected`; a non-zero spool on a host that was not faulted at the
end of its day; a drift row on a host whose content you did not change; a label count other than the one you set; a
collector WARNING or ERROR line. Anything else that differs from the table is a finding, to be explained, which does
not fail the soak by itself. The injected faults are expected to produce exactly the 401, 403, spool and replay
numbers in section 5, and no others.

| Measure | Where it comes from | Fails when (healthy day) | Expected |
|---|---|---|---|
| Ingest success rate | observer: 200 / all ingest calls | below 100% on a healthy day | 100% on healthy days. Lower only on injected-fault days, with the 401 explained |
| Duplicates | the day-6 replay only | any duplicate other than the replay (a bundle stored twice by a retry) | 1 |
| 429 | observer, access log | any | 0 (burst 10, one refill a minute, one post a day) |
| 503 | observer, access log | any | 0 |
| Spool depth per host | host CSV | above 0 on a host that is not faulted | 0 except during an injected fault |
| Rejected files per host | host CSV | any | 0 |
| Agent exit code | host CSV | any value other than 0 | 0 everywhere, always (a spooled report exits 0) |
| Drift rows per host per day | observer | above 0 on a host whose content you did not change | 0, except the host whose content you changed, on that day |
| Pruned per day | observer, `old_scans_gone_total` | a host above the retention number of scans | 0 until a host holds more than the retention number |
| Labels per host | observer | any count other than the one you set | 3, constant |
| Stale hosts | `/fleet` or `pqcscan fleet summary` | any host flagged stale | none (a host unseen for 48 h is flagged) |

3. List every non-zero that the table does not predict under **Findings**. Do not average them away. For each one:
   the host, the day, the log line or drift sample, and whether it reproduces. The simulation's two product bugs
   (a timestamp in a finding title, and open ports that vanished from a scan on a loaded box) both showed up as
   drift on hosts where nothing had changed, and both were explained only because the drift rows were printed.
   Keep `drift_sample` in the report.
4. Commit the result JSON, the host CSV and a `SOAK-REAL.md` with the filled table. Name the commit the hosts ran,
   the DB, the OS mix, and which faults you injected. Until that exists, every claim `SOAK.md` supports stays labelled
   "simulated".

## What a real run can show that the simulation cannot

- Windows: the `-RunAs` account, ACLs on `%ProgramData%\pqcscan`, the Scheduled Task's behaviour when the machine is
  asleep or off at 02:00, and whether `LastTaskResult` is 0 after a spooled report.
- Real network faults: a TCP reset mid-upload, a proxy that adds basic auth on `/api/ingest`, a TLS certificate that
  expires on day 4.
- Real clock behaviour: DST changes, NTP steps, hosts whose clocks differ from the collector's.
- Real scan content: hosts whose findings really change day to day (patching, new listeners). Drift above 0 there is
  expected. The question is whether each drift row matches a change you can name.
- Seven days of retention and of `last_seen`, which the simulation compresses into minutes.
