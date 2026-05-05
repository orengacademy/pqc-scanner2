"""k8s.mesh.mtls — detect Istio / Linkerd via kubectl get crd."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class K8sMeshMtls(Probe):
    id = "k8s.mesh.mtls"
    family = ProbeFamily.CONTAINER
    requires = frozenset({Capability.KUBECTL})
    framework_tags = ("bukukerja:k8s", "mykripto:k8s")

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            Capability.KUBECTL in ctx.available_capabilities
            and shutil.which("kubectl") is not None
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "get", "crd", "-o", "name",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        if "istio.io" in text:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title="Istio service mesh detected (mTLS via Citadel/Pilot)",
                evidence={"signal": "istio.io CRD present"},
            ))
        if "linkerd.io" in text:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title="Linkerd service mesh detected (mTLS via control plane)",
                evidence={"signal": "linkerd.io CRD present"},
            ))
