"""cve.pip_audit — pip-audit (PyPA, Apache-2.0) Python dep CVE scanner."""
from __future__ import annotations

import asyncio
import json

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


class CvePipAudit(Probe):
    id = "cve.pip_audit"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(self, pip_audit_bin: str | None = None, timeout_s: float = 120.0):
        self.bin = pip_audit_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return resolve_or_none(self.bin, "pip-audit") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.bin, "pip-audit")
        if bin_path is None:
            return
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), "--format", "json", "--strict",
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
        for dep in doc.get("dependencies", []) or []:
            for vuln in dep.get("vulns", []) or []:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"{vuln.get('id', '?')} affects {dep.get('name', '?')} {dep.get('version', '?')}",
                    evidence={"package": dep.get("name", ""),
                              "version": dep.get("version", ""),
                              "vuln_id": vuln.get("id", ""),
                              "fix_versions": vuln.get("fix_versions", [])},
                ))
