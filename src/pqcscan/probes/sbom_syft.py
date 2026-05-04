"""sbom.syft — alternate SBOM generator via Anchore Syft (Apache-2.0).

Detects the `syft` binary via the offline-pack resolver (env override →
PyInstaller MEIPASS bundle → system PATH). When present, runs:
    syft <target> -o cyclonedx-json
parses the package list, and emits one INFO finding per component.

Use case: cross-check vs the native sbom.os.* probes; cover ecosystems
where pqcscan doesn't have a native parser yet (rust, java, php, etc.).
"""
from __future__ import annotations

import asyncio
import json

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.offline_pack import resolve_or_none


class SbomSyft(Probe):
    id = "sbom.syft"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, target: str = "dir:/", syft_bin: str | None = None,
                 timeout_s: float = 120.0):
        self.target = target
        self.syft_bin = syft_bin
        self.timeout_s = timeout_s

    def _resolve(self):
        return resolve_or_none(self.syft_bin, "syft")

    async def applies(self, ctx: ScanContext) -> bool:
        return self._resolve() is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self._resolve()
        if bin_path is None:
            return
        proc = await asyncio.create_subprocess_exec(
            str(bin_path), self.target, "-o", "cyclonedx-json", "--quiet",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return
        try:
            sbom = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for c in sbom.get("components", []) or []:
            name = c.get("name", "")
            version = c.get("version", "")
            purl = c.get("purl", "")
            if not name:
                continue
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"package: {name} {version}".strip(),
                evidence={
                    "name": name, "version": version,
                    "purl": purl, "source": "syft",
                    "type": c.get("type", ""),
                },
            ))
