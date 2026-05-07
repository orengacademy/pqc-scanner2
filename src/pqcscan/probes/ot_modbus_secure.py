"""ot.modbus_secure.tls — wraps _tls_probe against Modbus-Secure (TCP/802)."""
from __future__ import annotations

import asyncio
import contextlib

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class OTModbusSecure(Probe):
    id = "ot.modbus_secure.tls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "modbus_secure") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "modbus_secure")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=802, proto_hint="modbus_secure")]
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
                    title=f"Modbus-Secure unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            await run_tls_probe(
                host=target.host, port=target.port, verify=False,
                probe_id=self.id, emit=emit,
            )
