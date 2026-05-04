"""net.smb.dialect — SMB2 Negotiate Protocol; flags SMB1 if server downgrades."""
from __future__ import annotations

import asyncio
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


# Build a NetBIOS session-service header + SMB2 NEGOTIATE request offering
# dialects 0x0202 (SMB 2.0.2), 0x0210 (2.1), 0x0300 (3.0), 0x0302 (3.0.2),
# 0x0311 (3.1.1).
def _smb2_negotiate() -> bytes:
    smb2_header = (
        b"\xfeSMB"
        + b"\x40\x00"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 16
    )
    dialects = b"\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03"
    body = (
        b"\x24\x00"
        + b"\x05\x00"
        + b"\x01\x00"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 16
        + b"\x00" * 8
        + dialects
    )
    smb2 = smb2_header + body
    nbss = b"\x00" + struct.pack(">I", len(smb2))[1:]  # 4-byte session-msg header
    return nbss + smb2


class NetSmbDialect(Probe):
    id = "net.smb.dialect"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:smb", "bukukerja:smb", "mykripto:smb")

    def __init__(self, host: str = "127.0.0.1", port: int = 445,
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
                title=f"SMB connection failed at {self.host}:{self.port}: {e}",
            ))
            return
        try:
            writer.write(_smb2_negotiate()); await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(1024), timeout=self.timeout_s)
            except asyncio.TimeoutError:
                return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        if len(resp) < 80 or resp[4:8] != b"\xfeSMB":
            # Not an SMB2 response — could be SMB1 server.
            if resp[4:8] == b"\xffSMB":
                emit(Finding(
                    probe_id=self.id, algorithm="SMBv1",
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=f"SMBv1 detected at {self.host}:{self.port}",
                    evidence={"endpoint": f"{self.host}:{self.port}"},
                ))
            return
        # SMB2 Negotiate Response: dialect_revision at offset 64+2 = 66 (16-bit LE).
        dialect = struct.unpack("<H", resp[68:70])[0]
        cls = Classification.TINGGI
        if dialect < 0x0300:
            cls = Classification.SANGAT_TINGGI  # SMB 2.0.x is deprecated
        emit(Finding(
            probe_id=self.id,
            algorithm=f"SMB-dialect-0x{dialect:04x}",
            classification=cls,
            severity=Severity.CRIT if cls is Classification.SANGAT_TINGGI else Severity.HIGH,
            title=f"SMB dialect 0x{dialect:04x} at {self.host}:{self.port}",
            evidence={"endpoint": f"{self.host}:{self.port}",
                      "dialect_hex": f"0x{dialect:04x}"},
        ))
