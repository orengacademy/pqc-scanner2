"""ot.dnp3.tcp — detects DNP3 outstations and DNP3 Secure Authentication state."""
from __future__ import annotations

import asyncio
import contextlib

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


def _dnp3_link_status_request() -> bytes:
    return bytes.fromhex("0564050901000000ffff")


class OTDnp3Tcp(Probe):
    id = "ot.dnp3.tcp"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "dnp3") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "dnp3")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=20000, proto_hint="dnp3")]
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
                    title=f"DNP3 unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_dnp3_link_status_request())
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
                except TimeoutError:
                    resp = b""
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            dnp3_observed = len(resp) >= 4 and resp[:2] == b"\x05\x64"
            secure_auth_present = b"\x78" in resp[8:32]
            emit(Finding(
                probe_id=self.id,
                algorithm="plain-DNP3" if not secure_auth_present else "DNP3-SA",
                classification=Classification.INFO,
                severity=Severity.HIGH if not secure_auth_present else Severity.MED,
                title=f"DNP3 outstation at {target.host}:{target.port}",
                evidence={
                    "endpoint": f"tcp://{target.host}:{target.port}",
                    "transport": "TCP",
                    "dnp3_observed": dnp3_observed,
                    "secure_auth_present": secure_auth_present,
                    "no_crypto": not secure_auth_present,
                    "response_len": len(resp),
                },
            ))
