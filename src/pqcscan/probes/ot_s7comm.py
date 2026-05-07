"""ot.s7comm — detects plain Siemens S7 protocol over TPKT/COTP/TCP."""
from __future__ import annotations

import asyncio
import contextlib

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _cotp_cr_request() -> bytes:
    cotp = bytes.fromhex("11e0000000010000c1020100c2020102c0010a")
    tpkt = b"\x03\x00" + (4 + len(cotp)).to_bytes(2, "big")
    return tpkt + cotp


class OTS7comm(Probe):
    id = "ot.s7comm"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "s7") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "s7")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=102, proto_hint="s7")]
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
                    title=f"S7 unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_cotp_cr_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
                except TimeoutError:
                    resp = b""
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            cotp_cc_ok = len(resp) >= 6 and resp[0] == 0x03 and resp[5] == 0xD0
            emit(Finding(
                probe_id=self.id,
                algorithm="plain-S7",
                classification=Classification.INFO,
                severity=Severity.HIGH,
                title=f"plain Siemens S7 at {target.host}:{target.port}",
                evidence={
                    "endpoint": f"tcp://{target.host}:{target.port}",
                    "plain_s7": cotp_cc_ok,
                    "transport": "TPKT/COTP/TCP",
                    "no_crypto": True,
                    "cotp_cc_observed": cotp_cc_ok,
                    "response_len": len(resp),
                },
            ))
