"""k8s.helm.releases — list Helm releases via `helm list`."""
from __future__ import annotations

import asyncio
import json
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class K8sHelmReleases(Probe):
    id = "k8s.helm.releases"
    family = ProbeFamily.CONTAINER
    framework_tags = ("bukukerja:k8s", "mykripto:k8s")

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which("helm") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            "helm", "list", "--all-namespaces", "-o", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except asyncio.TimeoutError:
            proc.kill()
            return
        try:
            releases = json.loads(stdout)
        except json.JSONDecodeError:
            return
        for r in releases:
            name = r.get("name", "?")
            namespace = r.get("namespace", "?")
            chart = r.get("chart", "?")
            status = r.get("status", "?")
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"helm release {namespace}/{name} chart={chart} status={status}",
                evidence={"namespace": namespace, "name": name,
                          "chart": chart, "status": status},
            ))
