"""net.kerberos.asreq — KDC reachability on TCP 88.

Emits an INFO finding when a KDC answers. Encryption-type grading (RC4/DES/
AES) is done by `net.kerberos.etypes`, which sends a real ASN.1 AS-REQ; this
probe only records that a Kerberos service exists so the inventory is
complete even when the etype probe is skipped.
"""
from __future__ import annotations

import asyncio
import contextlib

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
        except (TimeoutError, OSError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"Kerberos KDC unreachable at {self.host}:{self.port}: {e}",
            ))
            return
        # Write a single zero byte to elicit a malformed-request response,
        # confirming KDC is alive without sending a full AS-REQ.
        try:
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(64), timeout=self.timeout_s)
        except (TimeoutError, OSError):
            resp = b""
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        emit(Finding(
            probe_id=self.id,
            algorithm="Kerberos",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"Kerberos KDC reachable at {self.host}:{self.port}",
            evidence={"endpoint": f"{self.host}:{self.port}",
                      "response_bytes": len(resp),
                      "etype_grading": "net.kerberos.etypes"},
        ))
