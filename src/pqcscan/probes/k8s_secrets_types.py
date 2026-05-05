"""k8s.secrets.types — flag kubernetes.io/tls secrets via kubectl."""
from __future__ import annotations

import asyncio
import json
import shutil

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class K8sSecretsTypes(Probe):
    id = "k8s.secrets.types"
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
            "kubectl", "get", "secrets", "--all-namespaces", "-o", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20.0)
        except TimeoutError:
            proc.kill()
            return
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for item in data.get("items", []):
            secret_type = item.get("type", "")
            if secret_type != "kubernetes.io/tls":
                continue
            name = item.get("metadata", {}).get("name", "?")
            namespace = item.get("metadata", {}).get("namespace", "?")
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"k8s tls secret {namespace}/{name}",
                evidence={"namespace": namespace, "name": name, "type": secret_type},
            ))
