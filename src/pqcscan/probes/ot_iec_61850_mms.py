"""ot.iec_61850.mms — IEC 61850 MMS Initiate over plain TCP/102."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _mms_initiate_request() -> bytes:
    return bytes.fromhex("030000160ee00000000100c1020100c2020102")


class OTIec61850Mms(Probe):
    id = "ot.iec_61850.mms"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "iec61850") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "iec61850")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=102, proto_hint="iec61850")]
        for target in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port), timeout=3.0,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as e:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"IEC-61850 MMS unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_mms_initiate_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            tpkt_ok = len(resp) >= 4 and resp[0] == 0x03 and resp[1] == 0x00
            emit(Finding(
                probe_id=self.id,
                algorithm="plain-MMS",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                title=f"plain IEC 61850 MMS at {target.host}:{target.port}",
                evidence={
                    "endpoint": f"tcp://{target.host}:{target.port}",
                    "transport": "ISO/TCP-102",
                    "plain_mms": tpkt_ok,
                    "no_crypto": True,
                    "iec_62351_4_tls_detected": False,
                    "response_len": len(resp),
                },
            ))
