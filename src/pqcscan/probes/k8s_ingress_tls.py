"""k8s.ingress.tls — list ingresses with TLS configuration via kubectl."""
from __future__ import annotations

import asyncio
import json
import shutil

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class K8sIngressTls(Probe):
    id = "k8s.ingress.tls"
    family = ProbeFamily.CONTAINER
    requires = frozenset({Capability.KUBECTL})
    framework_tags = ("bukukerja:k8s", "mykripto:k8s", "nist-ir-8547:tls")

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            Capability.KUBECTL in ctx.available_capabilities
            and shutil.which("kubectl") is not None
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "get", "ingresses", "--all-namespaces", "-o", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except asyncio.TimeoutError:
            proc.kill()
            return
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for item in data.get("items", []):
            name = item.get("metadata", {}).get("name", "?")
            namespace = item.get("metadata", {}).get("namespace", "?")
            for tls in item.get("spec", {}).get("tls", []):
                hosts = tls.get("hosts", [])
                secret = tls.get("secretName", "<inline>")
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"ingress {namespace}/{name} TLS hosts={hosts} secret={secret}",
                    evidence={"namespace": namespace, "name": name,
                              "hosts": hosts, "secret": secret},
                ))
