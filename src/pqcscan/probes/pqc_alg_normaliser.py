from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext


class PqcAlgNormaliser(Probe):
    """Meta-probe: the algorithm normaliser lives in core.alg and is consumed
    by other probes. This Probe class is a placeholder so the registry can
    list it."""

    id = "pqc.alg.normaliser"
    family = ProbeFamily.PQC_META
    enabled_default = False

    async def applies(self, ctx: ScanContext) -> bool:
        return False

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        return None
