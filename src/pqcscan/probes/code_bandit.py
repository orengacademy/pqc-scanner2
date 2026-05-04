"""code.bandit — Bandit (Apache-2.0) Python SAST."""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_SEV = {
    "HIGH":   (Classification.SANGAT_TINGGI, Severity.CRIT),
    "MEDIUM": (Classification.TINGGI, Severity.HIGH),
    "LOW":    (Classification.SEDERHANA, Severity.MED),
}


class CodeBandit(Probe):
    id = "code.bandit"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code")

    def __init__(self, roots: list[Path] | None = None,
                 bandit_bin: str | None = None, timeout_s: float = 180.0):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]
        self.bandit_bin = bandit_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.bandit_bin or "bandit") is not None and any(
            r.exists() for r in self.roots
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.bandit_bin or "bandit"
        for root in self.roots:
            if not root.exists():
                continue
            proc = await asyncio.create_subprocess_exec(
                bin_path, "-r", "-q", "-f", "json", str(root),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
            except asyncio.TimeoutError:
                proc.kill()
                continue
            try:
                doc = json.loads(stdout)
            except json.JSONDecodeError:
                continue
            for r in doc.get("results", []) or []:
                sev_label = r.get("issue_severity", "LOW")
                cls, sev = _SEV.get(sev_label, (Classification.INFO, Severity.INFO))
                emit(Finding(
                    probe_id=self.id,
                    algorithm=r.get("test_id", "N/A"),
                    classification=cls, severity=sev,
                    title=f"bandit {r.get('test_id', '')}: {r.get('issue_text', '')[:120]}",
                    evidence={"file": r.get("filename", ""),
                              "line": r.get("line_number", 0),
                              "test_id": r.get("test_id", ""),
                              "test_name": r.get("test_name", ""),
                              "confidence": r.get("issue_confidence", "")},
                ))
