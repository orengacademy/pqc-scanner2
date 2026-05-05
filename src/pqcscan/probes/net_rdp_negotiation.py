"""net.rdp.negotiation — RDP X.224 Connection Request / Negotiation Response."""
from __future__ import annotations

import asyncio
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# X.224 Connection Request with RDP Negotiation Request (request all protocols).
_CR = bytes.fromhex(
    "03 00 00 13"  # TPKT header (length 19)
    "0e e0 00 00 00 00 00"  # X.224 CR
    "01 00 08 00"  # Negotiation Request type 1, length 8
    "0b 00 00 00"  # requested protocols: PROTOCOL_RDP|SSL|HYBRID|HYBRID_EX
    .replace(" ", "")
)


class NetRdpNegotiation(Probe):
    id = "net.rdp.negotiation"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:rdp", "bukukerja:rdp", "mykripto:rdp")

    def __init__(self, host: str = "127.0.0.1", port: int = 3389,
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
                title=f"RDP connection failed at {self.host}:{self.port}: {e}",
            ))
            return
        try:
            writer.write(_CR); await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(64), timeout=self.timeout_s)
            except TimeoutError:
                return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        if len(resp) < 19:
            return
        # Negotiation Response starts at offset 11 of the X.224 CC.
        # type (1 byte): 2=NEG_RSP, 3=NEG_FAILURE
        # selected_protocol at offset 15..18 if NEG_RSP.
        neg_type = resp[11] if len(resp) > 11 else 0
        if neg_type == 2:
            selected = struct.unpack("<I", resp[15:19])[0]
            cls = Classification.TINGGI
            sev = Severity.HIGH
            if selected == 0:  # PROTOCOL_RDP — no NLA, classic RDP enc
                cls = Classification.SANGAT_TINGGI
                sev = Severity.CRIT
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RDP-protocol-{selected}",
                classification=cls, severity=sev,
                title=f"RDP at {self.host}:{self.port} selected protocol={selected}",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "selected_protocol": selected},
            ))
        elif neg_type == 3:
            failure = struct.unpack("<I", resp[15:19])[0] if len(resp) >= 19 else 0
            emit(Finding(
                probe_id=self.id, algorithm="RDP-NEG-FAILURE",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"RDP at {self.host}:{self.port} negotiation failure code={failure}",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "failure_code": failure},
            ))
