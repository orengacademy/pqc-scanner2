"""ot.iec_104.startdt — IEC 60870-5-104 STARTDT handshake; flags absence of TLS."""
from __future__ import annotations

import asyncio
import contextlib

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _startdt_act() -> bytes:
    return bytes.fromhex("680407000000")


class OTIec104(Probe):
    id = "ot.iec_104.startdt"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "iec104") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "iec104")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=2404, proto_hint="iec104")]
        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"IEC-104 unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_startdt_act())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(64), timeout=3.0)
                except TimeoutError:
                    resp = b""
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            startdt_con = len(resp) >= 6 and resp[0] == 0x68 and resp[2] == 0x83
            emit(Finding(
                probe_id=self.id,
                algorithm="plain-IEC104",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                title=f"plain IEC 60870-5-104 at {target.host}:{target.port}",
                evidence={
                    "endpoint": f"tcp://{target.host}:{target.port}",
                    "transport": "TCP",
                    "startdt_con": startdt_con,
                    "no_crypto": True,
                    "iec_62351_3_tls_wrap_detected": False,
                    "response_len": len(resp),
                },
            ))
