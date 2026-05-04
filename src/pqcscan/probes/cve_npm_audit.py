"""cve.npm_audit — `npm audit --json` for Node.js dep CVEs."""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_SEV = {
    "critical": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "high":     (Classification.TINGGI, Severity.HIGH),
    "moderate": (Classification.SEDERHANA, Severity.MED),
    "low":      (Classification.RENDAH, Severity.LOW),
    "info":     (Classification.INFO, Severity.INFO),
}


class CveNpmAudit(Probe):
    id = "cve.npm_audit"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(self, roots: list[Path] | None = None, npm_bin: str | None = None,
                 timeout_s: float = 60.0):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]
        self.npm_bin = npm_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.npm_bin or "npm") is not None and any(
            (r / "package.json").exists() if r.is_dir() else False for r in self.roots
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.npm_bin or "npm"
        for root in self.roots:
            if not (root.is_dir() and (root / "package.json").exists()):
                # Try nested package.json files.
                for nested in (root.rglob("package.json") if root.is_dir() else []):
                    if "node_modules" in nested.parts:
                        continue
                    await self._audit_one(bin_path, nested.parent, emit)
                continue
            await self._audit_one(bin_path, root, emit)

    async def _audit_one(self, bin_path: str, cwd: Path, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            bin_path, "audit", "--json",
            cwd=str(cwd),
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
        for name, advisory in (doc.get("vulnerabilities", {}) or {}).items():
            sev_label = advisory.get("severity", "info").lower()
            cls, sev = _SEV.get(sev_label, (Classification.INFO, Severity.INFO))
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=cls, severity=sev,
                title=f"npm audit {sev_label} on {name} (in {cwd})",
                evidence={"package": name, "severity": sev_label,
                          "via": str(advisory.get("via", "")), "cwd": str(cwd)},
            ))
