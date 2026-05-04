"""cve.osv_offline — STUB. Vendoring the OSV.dev mirror is a packaging task.

The plan-A spec calls for bundling an OSV.dev snapshot inside the
PyInstaller artefact and matching SBOM components against it offline.
v0.1.0 emits a deferral notice so the probe shows up in the registry
and the placeholder can be filled in once the offline pack lands.
"""
from __future__ import annotations

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class CveOsvOffline(Probe):
    id = "cve.osv_offline"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    async def applies(self, ctx: ScanContext) -> bool:
        return True  # always emits the deferral so users know it's tracked

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        emit(Finding(
            probe_id=self.id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=("OSV.dev offline CVE matching not yet implemented; "
                   "use cve.grype for online vuln data"),
            evidence={
                "deferred_to": "Plan F — PyInstaller offline pack with OSV.dev snapshot",
            },
        ))
