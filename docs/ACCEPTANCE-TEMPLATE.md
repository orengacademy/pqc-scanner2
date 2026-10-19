# Fleet Acceptance Sign-off

**Status: the acceptance run for the RFQ prospect is blocked.** It cannot start until the prospect gives us
two things: (1) access to a set of hosts on which the pqcscan agent can run, and (2) an export of their own asset
inventory for those hosts. Nothing in this repository stands in for that data, and no acceptance result exists yet.
Please provide:

- **Hosts.** The list of hosts to enroll, the environments they belong to (for example prod, DR, test), and
  permission to install the agent and reach the collector URL over HTTPS from each of them.
- **Inventory export.** A CSV with these columns. Only `hostname` is required; fill the rest wherever you hold the data.

  | Column | Meaning |
  |---|---|
  | `hostname` | Name the host is known by in your inventory |
  | `machine_id` | Optional. `/etc/machine-id` or equivalent; gives an exact match |
  | `owner` | Team or person accountable for the host |
  | `environment` | prod, dr, test, and so on |
  | `expected_tls_min` | Lowest TLS version you allow, for example `TLSv1.2` |
  | `expected_cert_cn` | Common name the host's certificate should carry |

- **Sign-off contacts.** Your security lead, and who may approve exceptions.
- **A scan window.** Enrolled hosts must report within 48 hours of the run, or they are listed as stale.

Everything below is filled in when the run happens. Tooling: `benchmark/fleet/reconcile.py`.

## 1. Scope

| Item | Value |
|---|---|
| Hosts in inventory | |
| Hosts enrolled and reporting | |
| Environments covered | |
| Environments excluded, and why | |

## 2. Run

| Item | Value |
|---|---|
| Run date (UTC) | |
| pqcscan version and commit | |
| Collector URL | |
| Inventory file and its SHA-256 | |

Commands used (edit to match the run):

```bash
pqcscan export --scan fleet --format cbom -o fleet.cbom.json
curl -s -H "Authorization: Bearer $TOKEN" "$COLLECTOR_URL/api/fleet" > fleet.json
python benchmark/fleet/reconcile.py --cbom fleet.cbom.json --fleet fleet.json \
    --inventory inventory.csv --out-dir acceptance/
echo "exit code: $?"    # 0 = no discrepancies, 1 = discrepancies, 2 = bad input
```

Attach `acceptance/discrepancies.csv` and `acceptance/discrepancies.md` to this sheet.

Read the "Not assessed" section of `discrepancies.md`. A check listed there was not performed, and it must be
resolved or written into the exceptions table. In particular, `cert_cn_mismatch` is only assessed when the CBOM
carries certificate subjects.

## 3. Discrepancy counts

| Class | Meaning | Count |
|---|---|---:|
| `missing_from_fleet` | In the inventory, never reported | |
| `unknown_to_inventory` | Reporting, not in the inventory | |
| `identity_mismatch` | Same machine_id with a different hostname, or the reverse | |
| `weak_match` | Matched on short name vs FQDN only; needs human confirmation | |
| `stale` | Last seen more than 48 hours before the run | |
| `revoked` | Agent token revoked | |
| `tls_below_expected` | A TLS finding below the host's `expected_tls_min` | |
| `cert_cn_mismatch` | Observed certificate CN differs from `expected_cert_cn` | |
| **Total** | | |

## 4. Decision

Mark one.

- [ ] **Accept.** Zero discrepancies, and nothing under "Not assessed".
- [ ] **Accept with exceptions.** Every remaining discrepancy appears in section 5 with an owner and a date.
- [ ] **Reject.** Reason:

## 5. Exceptions

| # | Host | Class | Reason it is acceptable | Owner | Remediate by |
|---|---|---|---|---|---|
| | | | | | |

## 6. Signatures

| Role | Name | Signature | Date |
|---|---|---|---|
| Prospect security lead | | | |
| Integrator | | | |
