"""ot.modbus.tcp — detects plain (unencrypted) Modbus/TCP devices."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _read_device_id_request(unit_id: int = 1, txn_id: int = 1) -> bytes:
    pdu = b"\x2b\x0e\x01\x00"
    mbap = (
        txn_id.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + bytes([unit_id])
    )
    return mbap + pdu


def _parse_read_device_id(resp: bytes) -> dict[str, Any]:
    if len(resp) < 7 + 8:
        return {}
    pdu = resp[7:]
    if pdu[:2] != b"\x2b\x0e":
        return {}
    n = pdu[6] if len(pdu) > 6 else 0
    out: dict[str, Any] = {"object_count": n}
    cursor = 7
    if n >= 1 and len(pdu) >= cursor + 2:
        obj_id = pdu[cursor]
        obj_len = pdu[cursor + 1]
        if len(pdu) >= cursor + 2 + obj_len:
            value = pdu[cursor + 2 : cursor + 2 + obj_len].decode("utf-8", errors="replace")
            if obj_id == 0:
                out["vendor_name"] = value
    return out


class OTModbusTcp(Probe):
    id = "ot.modbus.tcp"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "modbus") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "modbus")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=502, proto_hint="modbus")]
        for target in targets:
            await self._probe_one(target, emit)

    async def _probe_one(self, target: OTTarget, emit: Emitter) -> None:
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
                title=f"Modbus/TCP unreachable at {target.host}:{target.port}",
                evidence={"reachable": False, "error": repr(e)},
            ))
            return
        try:
            writer.write(_read_device_id_request())
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
            except (TimeoutError, asyncio.TimeoutError):
                resp = b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        parsed = _parse_read_device_id(resp)
        emit(Finding(
            probe_id=self.id,
            algorithm="plain-Modbus",
            classification=Classification.INFO,
            severity=Severity.HIGH,
            title=f"plain Modbus/TCP at {target.host}:{target.port}",
            evidence={
                "endpoint": f"tcp://{target.host}:{target.port}",
                "plain_modbus": True,
                "transport": "TCP",
                "no_crypto": True,
                "response_len": len(resp),
                **parsed,
            },
        ))
