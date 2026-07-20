from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pqcscan import __version__
from pqcscan.store.repo import Repo


def build_cbom(repo: Repo, scan_id: int) -> dict[str, Any]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)

    components: list[dict[str, Any]] = []
    for f in findings:
        if f.algorithm == "N/A":
            continue
        ev = f.evidence or {}
        confidence = ev.get("confidence", "high")
        comp: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": f"finding-{f.id}",
            "name": f.algorithm,
            "description": f.title,
            "cryptoProperties": {
                "assetType": _asset_type_for(f.probe_id),
                "algorithmProperties": {
                    "primitive": _primitive_for(f.algorithm),
                    "parameterSetIdentifier": f.algorithm,
                    "executionEnvironment": "software-plain-ram",
                    "nistQuantumSecurityLevel": _nist_level_for(f.classification),
                },
            },
            # Provenance: detection confidence + probe, so a downstream CBOM
            # consumer can triage probabilistic (regex/name) detections.
            "properties": [
                {"name": "pqcscan:confidence", "value": confidence},
                {"name": "pqcscan:probe", "value": f.probe_id},
            ],
        }
        path = ev.get("path") or ev.get("file")
        if isinstance(path, str) and path:
            comp["evidence"] = {"occurrences": [{"location": path}]}
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [
                {"vendor": "pqcscan", "name": "pqcscan", "version": __version__}
            ],
            "component": {
                "type": "device",
                "name": scan.host_fingerprint or "host",
                "bom-ref": f"host-scan-{scan_id}",
            },
        },
        "components": components,
    }


def _asset_type_for(probe_id: str) -> str:
    if probe_id.startswith("net."):
        return "protocol"
    if probe_id.startswith("fs.cert"):
        return "certificate"
    if probe_id.startswith("fs.privkey") or probe_id.endswith(".privkey"):
        return "key"
    return "algorithm"


def _primitive_for(algorithm: str) -> str:
    a = algorithm.upper()
    if a.startswith(("RSA", "ECDSA", "DSA", "ED25519", "ED448",
                     "ML-DSA", "SLH-DSA", "FALCON")):
        return "signature"
    if a.startswith(("AES", "CHACHA")):
        return "cipher"
    if a.startswith(("SHA", "MD")):
        return "hash"
    if a.startswith(("ML-KEM", "X25519MLKEM", "ECDH", "DH")):
        return "key-agreement"
    return "other"


def _nist_level_for(classification: str) -> int:
    return {
        "pqc-ready": 3,
        "rendah": 2,
        "sederhana": 1,
        "tinggi": 0,
        "sangat-tinggi": 0,
        "info": 0,
        "error": 0,
    }.get(classification, 0)
