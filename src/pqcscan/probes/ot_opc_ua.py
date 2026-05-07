"""ot.opc_ua.endpoint_security — OPC UA GetEndpoints + SecurityPolicy classification."""
from __future__ import annotations

import asyncio
import re

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext


_POLICY_RE = re.compile(rb"SecurityPolicy#([A-Za-z0-9_]+)")


def _parse_security_policies(blob: bytes) -> list[str]:
    return [m.decode("ascii") for m in _POLICY_RE.findall(blob)]


_HELLO_FRAME = bytes.fromhex(
    "48454c4658000000ffffff7f00000100"
    "0000000020000000"
)


class OTOpcUa(Probe):
    id = "ot.opc_ua.endpoint_security"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "opcua") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "opcua")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=4840, proto_hint="opcua")]
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
                    title=f"OPC UA unreachable at {target.host}:{target.port}",
                    evidence={"reachable": False, "error": repr(e)},
                ))
                continue
            try:
                writer.write(_HELLO_FRAME)
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(8192), timeout=3.0)
                except (TimeoutError, asyncio.TimeoutError):
                    resp = b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            policies = _parse_security_policies(resp)
            if not policies:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"OPC UA no SecurityPolicy URI parsed at {target.host}:{target.port}",
                    evidence={"reason": "no policies in response", "response_len": len(resp)},
                ))
                continue
            for pol in policies:
                if pol in ("Basic128Rsa15", "Basic256"):
                    sev = Severity.HIGH
                    cls = Classification.SANGAT_TINGGI
                elif pol == "None":
                    sev = Severity.HIGH
                    cls = Classification.INFO
                else:
                    sev = Severity.MED
                    cls = classify(pol) if classify else Classification.INFO
                emit(Finding(
                    probe_id=self.id,
                    algorithm=pol,
                    classification=cls,
                    severity=sev,
                    title=f"OPC UA SecurityPolicy {pol} at {target.host}:{target.port}",
                    evidence={
                        "endpoint": f"tcp://{target.host}:{target.port}",
                        "security_policy_uri": f"http://opcfoundation.org/UA/SecurityPolicy#{pol}",
                        "transport": "OPC-UA-binary",
                    },
                ))
