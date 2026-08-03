from __future__ import annotations

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.util.clock import utcnow


class AuxClockCertValidity(Probe):
    id = "aux.clock.cert_validity"
    family = ProbeFamily.AUX

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        now = utcnow()
        emit(Finding(
            probe_id=self.id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"system UTC clock at scan: {now.isoformat()}",
            evidence={"utc_now": now.isoformat()},
        ))
