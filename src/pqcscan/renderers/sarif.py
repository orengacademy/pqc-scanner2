"""SARIF 2.1.0 renderer.

Emits a scan as a Static Analysis Results Interchange Format log so pqcscan
findings surface natively in GitHub Code Scanning (and any SARIF-aware
viewer). Each probe becomes a `rule`; each finding becomes a `result` linked
to that rule, carrying the PQC classification, the migration target from the
remediation enrichment, and — when a probe recorded an on-disk `path` — a
physical location so the finding annotates the right file.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqcscan import __version__
from pqcscan.store.repo import Repo

_INFO_URI = "https://github.com/orengacademy/pqc-scanner2"

# pqcscan classification/severity → SARIF result level.
_LEVEL_BY_SEVERITY: dict[str, str] = {
    "crit": "error",
    "high": "error",
    "med": "warning",
    "low": "note",
    "info": "note",
}

# GitHub reads properties.security-severity (0.0-10.0) to bucket alerts.
_SECURITY_SEVERITY: dict[str, str] = {
    "crit": "9.5",
    "high": "8.0",
    "med": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _rule_for(probe_id: str) -> dict[str, Any]:
    return {
        "id": probe_id,
        "name": "".join(part.capitalize() for part in probe_id.replace(".", "_").split("_")),
        "shortDescription": {"text": f"pqcscan probe {probe_id}"},
        "fullDescription": {
            "text": (
                f"Post-quantum readiness finding from the {probe_id} probe. "
                "See the finding message for the affected algorithm and the "
                "recommended NIST PQC migration target."
            )
        },
        "helpUri": f"{_INFO_URI}/blob/main/docs/STATUS.md",
        "defaultConfiguration": {"level": "warning"},
    }


def _result_for(f: Any) -> dict[str, Any]:
    severity = str(f.severity)
    level = _LEVEL_BY_SEVERITY.get(severity, "note")

    message = f.title
    remediation = f.remediation or {}
    if remediation.get("replacement"):
        message += f"  → migrate to {remediation['replacement']}"
        if remediation.get("deadline"):
            message += f" by {remediation['deadline']}"

    confidence = (f.evidence or {}).get("confidence", "high")
    result: dict[str, Any] = {
        "ruleId": f.probe_id,
        "level": level,
        "message": {"text": message},
        "properties": {
            "algorithm": f.algorithm,
            "classification": str(f.classification),
            "security-severity": _SECURITY_SEVERITY.get(severity, "1.0"),
            "confidence": confidence,
        },
    }
    if remediation.get("replacement"):
        result["properties"]["pqc_replacement"] = remediation["replacement"]
    if remediation.get("deadline"):
        result["properties"]["migration_deadline"] = remediation["deadline"]
    if remediation.get("hndl"):
        result["properties"]["harvest_now_decrypt_later"] = True
    # Per-language before/after fix, so SARIF consumers (Security tab, CI) show
    # a concrete remediation snippet alongside the finding.
    snippet = remediation.get("snippet")
    if isinstance(snippet, dict) and snippet.get("after"):
        result["properties"]["pqc_fix_before"] = snippet.get("before", "")
        result["properties"]["pqc_fix_after"] = snippet["after"]

    # Physical location when a probe recorded a filesystem path in evidence.
    path = (f.evidence or {}).get("path")
    if isinstance(path, str) and path:
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": _as_uri(path)},
            }
        }]
    return result


def _as_uri(path: str) -> str:
    # SARIF artifactLocation.uri prefers relative or file: URIs; absolute
    # POSIX paths are kept as-is under a file scheme so viewers resolve them.
    if path.startswith(("/", "\\")):
        return "file://" + path
    return path


def build_sarif(repo: Repo, scan_id: int) -> dict[str, Any]:
    findings = repo.list_findings(scan_id)

    rules: dict[str, dict[str, Any]] = {}
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        if f.probe_id not in rules:
            rule_index[f.probe_id] = len(rules)
            rules[f.probe_id] = _rule_for(f.probe_id)
        result = _result_for(f)
        result["ruleIndex"] = rule_index[f.probe_id]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pqcscan",
                    "version": __version__,
                    "informationUri": _INFO_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def render_sarif(repo: Repo, scan_id: int, out: Path) -> None:
    out.write_text(json.dumps(build_sarif(repo, scan_id), indent=2))
