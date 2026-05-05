"""container.image.sbom — list running container images via docker/podman."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class ContainerImageSbom(Probe):
    id = "container.image.sbom"
    family = ProbeFamily.CONTAINER
    requires = frozenset({Capability.CONTAINER_RT})
    framework_tags = ("bukukerja:container", "mykripto:container")

    async def applies(self, ctx: ScanContext) -> bool:
        if Capability.CONTAINER_RT not in ctx.available_capabilities:
            return False
        return shutil.which("docker") is not None or shutil.which("podman") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = shutil.which("docker") or shutil.which("podman")
        if not bin_path:
            return
        proc = await asyncio.create_subprocess_exec(
            bin_path, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except TimeoutError:
            proc.kill()
            return
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.endswith(":<none>"):
                continue
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"container image present: {line}",
                evidence={"image": line, "runtime": bin_path},
            ))
