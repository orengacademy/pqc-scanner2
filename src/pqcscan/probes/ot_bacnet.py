"""ot.bacnet.bvlc — BACnet/IP Who-Is over UDP/47808; flags absence of BACnet/SC."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _who_is() -> bytes:
    bvlc = b"\x81\x0b\x00\x0c"
    npdu = b"\x01\x20"
    apdu = b"\x10\x08"
    return bvlc + npdu + apdu


class OTBacnet(Probe):
    id = "ot.bacnet.bvlc"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "bacnet") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "bacnet")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=47808, proto_hint="bacnet")]
        for target in targets:
            await self._probe_one(target, emit)

    async def _probe_one(self, target: OTTarget, emit: Emitter) -> None:
        loop = asyncio.get_running_loop()
        future_resp: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: Any) -> None:
                if not future_resp.done():
                    future_resp.set_result(data)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(target.host, target.port),
            )
        except OSError as e:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"BACnet unreachable at {target.host}:{target.port}",
                evidence={"reachable": False, "error": repr(e)},
            ))
            return
        try:
            transport.sendto(_who_is())
            try:
                resp = await asyncio.wait_for(future_resp, timeout=2.0)
            except TimeoutError:
                resp = b""
        finally:
            transport.close()

        bvlc_ok = len(resp) >= 4 and resp[0] == 0x81
        emit(Finding(
            probe_id=self.id,
            algorithm="plain-BACnet",
            classification=Classification.INFO,
            severity=Severity.HIGH,
            title=f"plain BACnet/IP at {target.host}:{target.port}",
            evidence={
                "endpoint": f"udp://{target.host}:{target.port}",
                "transport": "UDP/47808",
                "plain_bacnet": bvlc_ok,
                "no_crypto": True,
                "bacnet_sc_detected": False,
                "response_len": len(resp),
            },
        ))
