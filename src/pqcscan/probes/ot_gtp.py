"""ot.gtp.cu — GTPv2-C / GTPv1-U Echo over UDP/2123 or 2152; flags absence of IPsec."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _gtpv2c_echo() -> bytes:
    return bytes.fromhex("4801000400000001")


class OTGtp(Probe):
    id = "ot.gtp.cu"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "gtp") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "gtp")]
        if not targets:
            targets = [
                OTTarget(host="127.0.0.1", port=2123, proto_hint="gtp"),
                OTTarget(host="127.0.0.1", port=2152, proto_hint="gtp"),
            ]
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
                title=f"GTP unreachable at {target.host}:{target.port}",
                evidence={"reachable": False, "error": repr(e)},
            ))
            return
        try:
            transport.sendto(_gtpv2c_echo())
            try:
                resp = await asyncio.wait_for(future_resp, timeout=2.0)
            except (TimeoutError, asyncio.TimeoutError):
                resp = b""
        finally:
            transport.close()

        gtp_ok = len(resp) >= 1 and (resp[0] >> 5) in (1, 2)
        emit(Finding(
            probe_id=self.id,
            algorithm="plain-GTP",
            classification=Classification.INFO,
            severity=Severity.HIGH,
            title=f"plain GTP at {target.host}:{target.port}",
            evidence={
                "endpoint": f"udp://{target.host}:{target.port}",
                "transport": "UDP",
                "plain_gtp": gtp_ok,
                "no_crypto": True,
                "ipsec_tunnel_detected_externally": False,
                "response_len": len(resp),
                "note": "Confirm IPsec wrap separately via net.ike.v1v2",
            },
        ))
