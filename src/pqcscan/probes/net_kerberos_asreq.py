"""net.kerberos.asreq — connect to Kerberos KDC, observe protocol behaviour.

Sending a full AS-REQ requires ASN.1 DER encoding which is non-trivial to
hand-roll. v0.1 just verifies the KDC is listening on TCP 88 and emits an
INFO finding so the framework registers Kerberos coverage; deep etype
analysis lands when we add an ASN.1 DER encoder.
"""
from __future__ import annotations

import asyncio

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class NetKerberosAsreq(Probe):
    id = "net.kerberos.asreq"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:kerberos", "bukukerja:kerberos", "mykripto:kerberos")

    def __init__(self, host: str = "127.0.0.1", port: int = 88,
                 timeout_s: float = 5.0):
        self.host, self.port, self.timeout_s = host, port, timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout_s,
            )
        except (OSError, asyncio.TimeoutError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"Kerberos KDC unreachable at {self.host}:{self.port}: {e}",
            ))
            return
        # Write a single zero byte to elicit a malformed-request response,
        # confirming KDC is alive without sending a full AS-REQ.
        writer.write(b"\x00\x00\x00\x00"); await writer.drain()
        try:
            resp = await asyncio.wait_for(reader.read(64), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            resp = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        emit(Finding(
            probe_id=self.id,
            algorithm="Kerberos",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title=f"Kerberos KDC at {self.host}:{self.port} (deep etype analysis pending)",
            evidence={"endpoint": f"{self.host}:{self.port}",
                      "response_bytes": len(resp),
                      "deferred_to": "ASN.1 DER AS-REQ encoder for full etype probe"},
        ))
