"""cve.grype — CVE matching against installed packages via Anchore Grype.

Runs `grype dir:/ -o json` and emits one Finding per (CVE, package) pair.
Severity is mapped from Grype severity → pqcscan Severity.
"""
from __future__ import annotations

import asyncio
import json

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none

_GRYPE_TO_SEV = {
    "Critical": Severity.CRIT,
    "High":     Severity.HIGH,
    "Medium":   Severity.MED,
    "Low":      Severity.LOW,
    "Negligible": Severity.INFO,
    "Unknown":  Severity.INFO,
}

_GRYPE_TO_CLASS = {
    "Critical": Classification.SANGAT_TINGGI,
    "High":     Classification.TINGGI,
    "Medium":   Classification.SEDERHANA,
    "Low":      Classification.RENDAH,
    "Negligible": Classification.INFO,
    "Unknown":  Classification.INFO,
}


class CveGrype(Probe):
    id = "cve.grype"
    family = ProbeFamily.SBOM  # CVE coverage is downstream of SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(self, target: str = "dir:/", grype_bin: str | None = None,
                 timeout_s: float = 180.0):
        self.target = target
        self.grype_bin = grype_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return resolve_or_none(self.grype_bin, "grype") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.grype_bin, "grype")
        if bin_path is None:
            return
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), self.target, "-o", "json", "--quiet",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_s,
            )
        except TimeoutError:
            proc.kill()
            return
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for match in doc.get("matches", []) or []:
            vuln = match.get("vulnerability", {}) or {}
            artifact = match.get("artifact", {}) or {}
            sev_label = vuln.get("severity", "Unknown")
            cve_id = vuln.get("id", "UNKNOWN-CVE")
            pkg = artifact.get("name", "?")
            version = artifact.get("version", "?")
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=_GRYPE_TO_CLASS.get(sev_label, Classification.INFO),
                severity=_GRYPE_TO_SEV.get(sev_label, Severity.INFO),
                title=f"{cve_id} affects {pkg} {version}",
                evidence={
                    "cve": cve_id,
                    "package": pkg,
                    "version": version,
                    "severity": sev_label,
                    "url": vuln.get("dataSource", ""),
                    "fix": (vuln.get("fix", {}) or {}).get("versions", []),
                },
            ))
