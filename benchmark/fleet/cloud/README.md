# Load box on DigitalOcean

A throwaway droplet that runs `benchmark/fleet` away from the shared workstation, so a result does not depend on what else the workstation is doing.

## Prerequisites

- `doctl` installed and logged in: `doctl auth init`.
- An SSH key imported into DigitalOcean under a name (default `pqc-campaign`):
  ```bash
  ssh-keygen -t ed25519 -N '' -f ~/.ssh/pqc_campaign_ed25519 -C pqc-campaign
  doctl compute ssh-key import pqc-campaign --public-key-file ~/.ssh/pqc_campaign_ed25519.pub
  ```
- `rsync` and `ssh` locally. Docker is not needed locally; the box installs it.
- The commit you want to measure is pushed to GitHub. The box clones `https://github.com/orengacademy/pqc-scanner2` (not your local `origin` remote) and checks out `PQC_REF` (default: your local `HEAD`, resolved to a full sha). If the commit is not there, setup fails and `up` says so.

## Commands

```bash
export PQC_SSH_KEY=~/.ssh/pqc_campaign_ed25519   # private key, passed as ssh -i; omit to use ssh defaults
bash benchmark/fleet/cloud/loadbox.sh up            # create pqc-loadbox, wait for setup (about 5-8 min), print the IP; refuses if it already exists
bash benchmark/fleet/cloud/loadbox.sh run before    # before | after | sweep | ratio-baseline | pg-insert | retention
bash benchmark/fleet/cloud/loadbox.sh wait          # block until the suite finishes; fails if it died or the box is unreachable
bash benchmark/fleet/cloud/loadbox.sh pull          # rsync results/, profiles/, LOAD.md and the suite log back here
bash benchmark/fleet/cloud/loadbox.sh down          # destroy the droplet
```

Environment: `DO_REGION` (`sgp1`), `DO_SIZE` (`s-8vcpu-16gb`), `DO_IMAGE` (`ubuntu-24-04-x64`), `DO_SSH_KEY` (`pqc-campaign`), `DO_NAME` (`pqc-loadbox`), `PQC_REF`, `PQC_SSH_KEY`.

The suites (see `suite.sh`):

| Mode | What it runs, per backend (sqlite, postgres) |
| --- | --- |
| `before` / `after` | 500 hosts, 4 posts/s, 300 s, with `--profile` into `profiles/<db>-before` or `-after` |
| `sweep` | the CAPACITY.md shape: 60 hosts at 0.5 posts/s, 100 at 1, 250 at 2, 300 at 3, 500 at 4, 6, 8 and 12; seeds 1 and 2, 300 s each; then a 180 s herd of 500 hosts. Postgres also runs 500 hosts at 4 and 6 posts/s with 2, 4 and 8 ingest slots |
| `pg-insert` | Postgres only: 500 hosts, 4 posts/s, insert mode `pages` and `executemany` at 2 and 4 slots |
| `retention` | keep 2 scans per host: SQLite 100 hosts at 1 post/s and Postgres 60 hosts at 0.5 posts/s, seeds 1 and 2, 300 s |
| `ratio-baseline` | 60 hosts at 1 post/s (60 s interval), 120 s, 1,670 findings per bundle (the CI load-ratio job's shape) |

To reproduce the capacity number, run the sweep at your commit and score it alone, not pooled with the committed rows:

```bash
bash benchmark/fleet/cloud/loadbox.sh up && bash benchmark/fleet/cloud/loadbox.sh run sweep
bash benchmark/fleet/cloud/loadbox.sh wait && bash benchmark/fleet/cloud/loadbox.sh pull
python -m benchmark.fleet.capacity --commit $(git rev-parse HEAD)   # rewrites CAPACITY.md from your rows only
```

`up` succeeds only when setup finished and the box is at the commit you asked for; if setup fails it exits 1 and the droplet is left running (and billing) for you to inspect, then `down`. Its host key is pinned per droplet in `benchmark/fleet/cloud/.loadbox_known_hosts` (gitignored): `up` starts a fresh file, `down` deletes it, because DigitalOcean recycles IPs.

Exit 1 from `run_load` means a FAIL row (p95 over 2 s) or request errors; the suite goes on. Any other non-zero exit is counted as a crash, printed as `CRASH exit N`, and the suite ends with a non-zero exit and a crash count. The log is `/root/suite.log` on the box; `pull` saves it as `benchmark/fleet/cloud/last-suite.log` (gitignored), so read it before `down`.

The box is pinned to the `PQC_REF` it was created with. The `after` suite needs `down`, then `up` with `PQC_REF` set to the new commit. A different droplet may have different CPUs, which the `box` field of each result records.

## What `pull` overwrites

`pull` rsyncs the box's `benchmark/fleet/results/`, `benchmark/fleet/profiles/` and `benchmark/fleet/LOAD.md` over the local copies. It does not delete local files, but `LOAD.md` is replaced whole: the box's copy is authoritative for rows the box produced. Commit or stash local `LOAD.md` edits first.

## Cost

US$0.14 an hour for `s-8vcpu-16gb`, billed while the droplet exists, powered off or not. Run `down` as soon as `pull` is done. A `before` run is about 15 minutes, a `sweep` about 3.5 hours.

## Provenance

`run_load` records the hardware in each result's `box` field (CPU count, model, memory) and in the `LOAD.md` head. A result from this box must be quoted as coming from it (DigitalOcean `s-8vcpu-16gb`, `sgp1`), never beside a workstation row as if the hardware were the same.
