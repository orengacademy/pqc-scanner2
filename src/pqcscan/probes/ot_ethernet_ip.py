"""ot.ethernet_ip.list_id — EtherNet/IP ListIdentity over plain TCP/44818."""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _list_identity_request() -> bytes:
    return b"\x63\x00" + b"\x00" * 22


class OTEthernetIp(Probe):
    id = "ot.ethernet_ip.list_id"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "enip") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "enip")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=44818, proto_hint="enip")]
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
                    title=f"EtherNet/IP unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_list_identity_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(512), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            enip_ok = len(resp) >= 4 and resp[:2] == b"\x63\x00"
            emit(Finding(
                probe_id=self.id,
                algorithm="plain-ENIP",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                title=f"plain EtherNet/IP at {target.host}:{target.port}",
                evidence={
                    "endpoint": f"tcp://{target.host}:{target.port}",
                    "transport": "TCP/44818",
                    "plain_enip": enip_ok,
                    "no_crypto": True,
                    "cip_security_detected": False,
                    "response_len": len(resp),
                },
            ))
