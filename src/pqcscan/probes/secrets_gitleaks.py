"""secrets.gitleaks — Gitleaks (MIT) secrets scanner. Finds hardcoded credentials.

Hardcoded secrets are an indirect PQC concern: long-lived plaintext API keys
and signing keys in source/config defeat the purpose of any cryptographic
strength below them. This probe surfaces them so the migration plan can
include rotation alongside algorithm uplift.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


class SecretsGitleaks(Probe):
    id = "secrets.gitleaks"
    family = ProbeFamily.SECRETS
    framework_tags = ("bukukerja:secrets", "mykripto:secrets")

    def __init__(self, roots: list[Path] | None = None,
                 gitleaks_bin: str | None = None, timeout_s: float = 180.0):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]
        self.gitleaks_bin = gitleaks_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return (resolve_or_none(self.gitleaks_bin, "gitleaks") is not None
                and any(r.exists() for r in self.roots))

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = resolve_or_none(self.gitleaks_bin, "gitleaks")
        if bin_path is None:
            return
        for root in self.roots:
            if not root.exists():
                continue
            proc = await asyncio.create_subprocess_exec(
                str(bin_path), "detect", "--no-git", "--report-format", "json",
                "--report-path", "-", "--source", str(root),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
            except asyncio.TimeoutError:
                proc.kill()
                continue
            try:
                doc = json.loads(stdout) or []
            except json.JSONDecodeError:
                continue
            for leak in doc:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=f"gitleaks: {leak.get('RuleID', '?')} at {leak.get('File', '')}:{leak.get('StartLine', 0)}",
                    evidence={"rule": leak.get("RuleID", ""),
                              "file": leak.get("File", ""),
                              "line": leak.get("StartLine", 0),
                              "match": leak.get("Match", "")[:120],
                              "secret_redacted": True},
                ))
