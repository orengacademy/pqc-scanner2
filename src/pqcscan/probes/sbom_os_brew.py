"""sbom.os.brew — macOS / Linuxbrew package list via subprocess `brew list --versions`."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomOsBrew(Probe):
    id = "sbom.os.brew"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, brew_bin: str | None = None, timeout_s: float = 30.0):
        self.brew_bin = brew_bin
        self.timeout_s = timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.brew_bin or "brew") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            self.brew_bin or "brew", "list", "--versions",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
        except TimeoutError:
            proc.kill()
            return
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
            emit_package(self.id, emit,
                         name=name, version=version,
                         manager="brew", purl_type="brew/homebrew")
