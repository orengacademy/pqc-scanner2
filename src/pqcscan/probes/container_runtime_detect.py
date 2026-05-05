"""container.runtime.detect — detect container runtimes installed on host."""
from __future__ import annotations

import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_RUNTIMES = ("docker", "podman", "containerd", "nerdctl", "crictl")


class ContainerRuntimeDetect(Probe):
    id = "container.runtime.detect"
    family = ProbeFamily.CONTAINER
    framework_tags = ("bukukerja:container", "mykripto:container")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(shutil.which(b) is not None for b in _RUNTIMES)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for binary in _RUNTIMES:
            located = shutil.which(binary)
            if located is None:
                continue
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"container runtime present: {binary}",
                evidence={"binary": binary, "path": located},
            ))
