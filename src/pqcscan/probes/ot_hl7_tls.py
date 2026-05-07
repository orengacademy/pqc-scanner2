"""ot.hl7.tls — MLLP over TLS (HL7 MLLPS) handshake on port 2575."""
from __future__ import annotations

import asyncio
import contextlib

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTHl7Tls(Probe):
    id = "ot.hl7.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "hl7") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "hl7")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=2575, proto_hint="hl7")]
        for target in targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=2.0,
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            except (OSError, TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"HL7-MLLPS unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
