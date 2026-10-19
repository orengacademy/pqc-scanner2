"""Offline fleet DB for the UI review: N hosts x M scans ingested through the daemon's own `Repo`.

Hosts are `soak-NNNN` (machine id `m-ui-NNNN`) labelled env=prod|dr|dev and site=dc0..dc4. Every bundle comes from
the load-test template (`_bundles`), so the wire format is the product's. The last bundle of every 10th host renames
one finding (title and evidence path: drift keys on the path when there is one), so the fleet page shows drift.

    python -m benchmark.fleet.make_fleet_db --hosts 500 --scans-per-host 2 --findings 1670 --out fleet.db
"""
from __future__ import annotations

import argparse
import copy
import tempfile
import time
from pathlib import Path

from pqcscan.store.bundle import HostIdentity, load_bundle
from pqcscan.store.repo import Repo

from ._bundles import build_template, host_bundle

ENVS = ("prod", "dr", "dev")


def _drifted(template: dict) -> dict:
    t = copy.deepcopy(template)
    f = t["findings"][0]
    f["title"] = f"{f['title']} (renamed)"
    f["evidence"] = {**f.get("evidence", {}), "path": f"{f.get('evidence', {}).get('path', '/etc/ssl/x')}.renamed"}
    return t


def build(out: Path, *, hosts: int, scans_per_host: int, findings: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        template = build_template(Path(tmp), findings)
    drifted = _drifted(template)
    repo = Repo(out)
    repo.init_schema()
    t0 = time.monotonic()
    for i in range(hosts):
        mid, name = f"m-ui-{i:04d}", f"soak-{i:04d}"
        labels = {"env": ENVS[i % len(ENVS)], "site": f"dc{i % 5}"}
        host = repo.upsert_host(HostIdentity(machine_id=mid, hostname=name, os="linux", labels=labels))
        for n in range(scans_per_host):
            tpl = drifted if (i % 10 == 0 and n == scans_per_host - 1 and n > 0) else template
            repo.ingest_bundle(load_bundle(host_bundle(tpl, mid, name, labels)), host.id)
    return {"hosts": hosts, "scans": hosts * scans_per_host, "findings": findings,
            "seconds": round(time.monotonic() - t0, 1)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hosts", type=int, default=500)
    ap.add_argument("--scans-per-host", type=int, default=2)
    ap.add_argument("--findings", type=int, default=1670)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    print(build(a.out, hosts=a.hosts, scans_per_host=a.scans_per_host, findings=a.findings))


if __name__ == "__main__":
    main()
