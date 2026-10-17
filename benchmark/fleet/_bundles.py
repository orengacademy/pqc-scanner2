"""Build host bundles for the load test from one template scan.

`build_template` stores `n_findings` findings through the real `Repo` and exports them with the real
`dump_bundle`, so the wire format is the product's own. `host_bundle` then derives one bundle per simulated
host by rewriting the host identity and scan_uuid. Every host therefore reports identical findings (same
paths, algorithms, views): the load test measures ingest cost per bundle, not content diversity.
`host_bundle` imports nothing from pqcscan so the locust process stays light.
"""
from __future__ import annotations

import gzip
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# (probe_id, algorithm, classification, severity): the mix a real scan stores, weak rows plus SBOM noise.
_WEAK = [
    ("trust.system_roots", "RSA-4096", "tinggi", "high"),
    ("trust.system_roots", "ECDSA-secp384r1", "tinggi", "high"),
    ("host.openssl.ciphers", "AES-128", "tinggi", "high"),
    ("trust.system_roots", "RSA-2048", "sangat-tinggi", "crit"),
    ("fs.cert.x509", "RSA-1024", "sangat-tinggi", "crit"),
]
_INFO = ("sbom.os.dpkg", "N/A", "info", "info")
_FRAMEWORKS = ("qramm", "au-asd-ism", "uk-ncsc", "ca-cccs", "eu-nis2", "anssi-pqc", "cnsa2")
_REMEDIATION = {"current": "RSA-2048", "replacement": "ML-KEM-768", "hybrid": "X25519MLKEM768", "standard": "FIPS 203",
                "kind": "key-establishment", "deadline": "2030-01-01", "hndl": True,
                "rationale": "Harvest-now-decrypt-later: migrate key establishment first."}


def build_template(workdir: Path, n_findings: int = 300) -> dict[str, Any]:
    """A bundle document (dict) with `n_findings` findings, 40% weak with 8 compliance views, the rest SBOM info."""
    from pqcscan.core.types import Classification, Finding, Severity
    from pqcscan.store.bundle import HostIdentity, dump_bundle
    from pqcscan.store.repo import Repo

    repo = Repo(workdir / "template.db")
    repo.init_schema()
    sid = repo.create_scan(mode="user", probe_versions={"trust.system_roots": "0.1.0"},
                           tool_versions={"python": "3.11"})
    for i in range(n_findings):
        probe, alg, cls, sev = _WEAK[i % len(_WEAK)] if i % 5 < 2 else _INFO
        fid = repo.record_finding(sid, Finding(
            probe_id=probe, algorithm=alg, classification=Classification(cls), severity=Severity(sev),
            title=f"{alg} item {i}", evidence={"path": f"/etc/ssl/item-{i}.pem", "subject": f"CN=item-{i}"},
            remediation=_REMEDIATION if sev != "info" else {}))
        repo.record_framework_view(fid, framework="nacsa-arahan-ke-9", clause="advisory", verdict="advisory",
                                   deadline=None)
        if sev != "info":
            for fw in _FRAMEWORKS:
                repo.record_framework_view(fid, framework=fw, clause="key-establishment", verdict="at-risk",
                                           deadline=None)
    repo.finish_scan(sid, status="done")
    raw = gzip.decompress(dump_bundle(repo, sid, HostIdentity(machine_id="template", hostname="template", os="linux")))
    return json.loads(raw)


def host_bundle(template: dict[str, Any], machine_id: str, hostname: str, labels: dict[str, str]) -> bytes:
    """gzip bundle for one host: template findings, fresh scan_uuid, scan times now (level 1 keeps client CPU low)."""
    now = datetime.now(UTC).isoformat()
    doc = {**template, "scan_uuid": str(uuid.uuid4()),
           "host": {"machine_id": machine_id, "hostname": hostname, "os": "linux", "labels": labels,
                    "agent_version": "load-test"},
           "scan": {**template["scan"], "started_at": now, "finished_at": now}}
    return gzip.compress(json.dumps(doc, separators=(",", ":")).encode(), compresslevel=1)
