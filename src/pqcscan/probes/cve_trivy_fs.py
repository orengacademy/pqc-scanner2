"""cve.trivy_fs — Aqua Trivy (Apache-2.0) filesystem scan, alternate to Grype."""
from __future__ import annotations

import asyncio
import json

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


_SEV = {
    "CRITICAL": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "HIGH":     (Classification.TINGGI, Severity.HIGH),
    "MEDIUM":   (Classification.SEDERHANA, Severity.MED),
    "LOW":      (Classification.RENDAH, Severity.LOW),
    "UNKNOWN":  (Classification.INFO, Severity.INFO),
}


class CveTrivyFs(Probe):
    id = "cve.trivy_fs"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(self, target: str = "/", trivy_bin: str | None = None,
                 timeout_s: float = 300.0):
        self.target = target
        self.trivy_bin = trivy_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return resolve_or_none(self.trivy_bin, "trivy") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.trivy_bin, "trivy")
        if bin_path is None:
            return
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), "fs", "--quiet", "--format", "json", self.target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            return
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for result in doc.get("Results", []) or []:
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities", []) or []:
                sev_label = v.get("Severity", "UNKNOWN")
                cls, sev = _SEV.get(sev_label, (Classification.INFO, Severity.INFO))
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=cls, severity=sev,
                    title=f"{v.get('VulnerabilityID', '?')} affects {v.get('PkgName', '?')} {v.get('InstalledVersion', '')}",
                    evidence={"target": target,
                              "cve": v.get("VulnerabilityID", ""),
                              "pkg": v.get("PkgName", ""),
                              "installed": v.get("InstalledVersion", ""),
                              "fixed": v.get("FixedVersion", ""),
                              "severity": sev_label},
                ))
