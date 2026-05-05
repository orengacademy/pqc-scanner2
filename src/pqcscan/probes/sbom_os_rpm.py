"""sbom.os.rpm — RHEL/Fedora package inventory via subprocess `rpm -qa`."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomOsRpm(Probe):
    id = "sbom.os.rpm"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, rpm_bin: str | None = None):
        self.rpm_bin = rpm_bin

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.rpm_bin or "rpm") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.rpm_bin or "rpm"
        proc = await asyncio.create_subprocess_exec(
            bin_path, "-qa", "--qf", "%{NAME}|%{VERSION}-%{RELEASE}\\n",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20.0)
        except TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if "|" not in line:
                continue
            name, version = line.split("|", 1)
            if name.strip():
                emit_package(self.id, emit,
                             name=name.strip(), version=version.strip(),
                             manager="rpm", purl_type="rpm")
