# CI/CD integration

Wire `pqcscan` into a pipeline so a build **fails** when it introduces
quantum-vulnerable crypto, and surface every finding in your platform's
security dashboard via SARIF. This mirrors how tools like `cryptoscan` and the
semgrep family ship a ready-made CI gate.

There are two moving parts:

1. the `--fail-on` **severity gate** on `pqcscan scan`, which sets the process
   exit code, and
2. **SARIF export** (`pqcscan export --format sarif`), which any SARIF-consuming
   platform (GitHub code scanning, GitLab, Azure DevOps, DefectDojo, …) can
   ingest.

---

## The `--fail-on` gate and exit codes

```bash
pqcscan scan --path . --fail-on high
```

`--fail-on [none|low|med|high|crit]` (default **`high`**) sets the threshold.
After the scan, the command exits **non-zero if any finding's severity is at or
above** the threshold. Severities rank `info < low < med < high < crit`, so
`--fail-on med` also fails on `high` and `crit`.

| `--fail-on` | Build fails when a finding is … |
| ----------- | ------------------------------- |
| `none`      | never (gate disabled — always exit 0 unless an error) |
| `low`       | `low`, `med`, `high`, or `crit` |
| `med`       | `med`, `high`, or `crit` |
| `high`      | `high` or `crit` *(default)* |
| `crit`      | `crit` only |

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Clean — no finding at or above `--fail-on` (or the gate is `none`). |
| `1`  | Gate tripped — at least one finding at or above the threshold. |
| `3`  | Internal error (bad arguments, unreadable DB, …). |

Both the human-readable output and `--json` report the threshold and the count
of findings at or above it:

```bash
pqcscan scan --path . --fail-on med --json
# {"scan_id": 1, "finding_count": 42, "high_or_crit_count": 3,
#  "fail_on": "med", "over_threshold_count": 7, "gate_tripped": true, ...}
```

> Report but don't block? Use `--fail-on none` and still export SARIF — the
> pipeline stays green while findings show up in the security dashboard.

---

## GitHub Actions (composite action + code scanning)

The repo ships a reusable composite action at its root. It downloads the pinned
Linux binary, runs the scan with your gate, and exports SARIF for
[`upload-sarif`](https://github.com/github/codeql-action) so findings land in
the **Security → Code scanning** tab.

```yaml
name: pqc-readiness
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for upload-sarif

jobs:
  pqcscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: scan
        uses: orengacademy/pqc-scanner2@v0.9.2
        with:
          version: v0.9.2
          path: .
          fail-on: high
          # target: example.com:8443   # optional TLS/STARTTLS endpoint

      # Upload even when the gate fails, so findings still reach the dashboard.
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif }}
```

Action inputs: `version` (release tag, default `v0.9.2`), `path` (scan path,
default `.`), `fail-on` (default `high`), `target` (optional network endpoint).
Output: `sarif` — the path to the exported SARIF file. The scan step fails the
job when the gate trips; `if: always()` on the upload step ensures findings are
still published.

---

## GitLab CI

GitLab reads SARIF-shaped reports via the `sast` artifact type, and the exit
code fails the job.

```yaml
pqcscan:
  image: debian:stable-slim
  variables:
    PQCSCAN_VERSION: v0.9.2
  before_script:
    - apt-get update && apt-get install -y curl
    - curl -fsSL -o /usr/local/bin/pqcscan
        "https://github.com/orengacademy/pqc-scanner2/releases/download/${PQCSCAN_VERSION}/pqcscan-linux-x86_64"
    - chmod +x /usr/local/bin/pqcscan
  script:
    - pqcscan scan --path . --fail-on high --db ./pqcscan.db
  after_script:
    - pqcscan export --scan 1 --format sarif -o pqcscan.sarif --db ./pqcscan.db
  artifacts:
    when: always
    reports:
      sast: pqcscan.sarif
    paths:
      - pqcscan.sarif
```

`after_script` runs regardless of the gate result, so the SARIF report is
attached even on a failed (gated) build.

---

## Generic shell (any CI, or a pre-commit / cron hook)

Download the binary, run the scan, and branch on the exit code:

```bash
#!/usr/bin/env bash
set -euo pipefail

VERSION=v0.9.2
curl -fsSL -o ./pqcscan \
  "https://github.com/orengacademy/pqc-scanner2/releases/download/${VERSION}/pqcscan-linux-x86_64"
chmod +x ./pqcscan

set +e
./pqcscan scan --path . --fail-on high --db ./pqcscan.db
code=$?
set -e

# Export SARIF regardless of the gate result.
./pqcscan export --scan 1 --format sarif -o pqcscan.sarif --db ./pqcscan.db

case "$code" in
  0) echo "pqcscan: clean" ;;
  1) echo "pqcscan: gate tripped — quantum-vulnerable crypto found"; exit 1 ;;
  3) echo "pqcscan: internal error"; exit 3 ;;
  *) echo "pqcscan: unexpected exit $code"; exit "$code" ;;
esac
```

Pin `VERSION` (and, for supply-chain assurance, verify the asset checksum as in
[`DEPLOYMENT.md`](DEPLOYMENT.md)) so builds are reproducible.

---

## SARIF works everywhere

`pqcscan export --format sarif` emits standard [SARIF
2.1.0](https://sariftools.github.io/). Beyond GitHub and GitLab, any
SARIF-consuming platform ingests it unchanged — Azure DevOps, DefectDojo,
Sonar, and the offline [SARIF viewer](https://microsoft.github.io/sarif-web-component/)
among them. The gate (`--fail-on`) and the report (SARIF) are independent: fail
the build on new high-severity crypto while still shipping the full inventory to
your dashboard.
