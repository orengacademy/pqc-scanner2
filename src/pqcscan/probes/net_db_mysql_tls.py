"""net.db.mysql_tls — read MySQL Initial Handshake Packet, parse capability flags."""
from __future__ import annotations

import asyncio
import contextlib
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_CLIENT_SSL_FLAG = 0x00000800  # CLIENT_SSL bit in MySQL capability flags


class NetDbMysqlTls(Probe):
    id = "net.db.mysql_tls"
    family = ProbeFamily.NETWORK
    framework_tags = ("bukukerja:db", "mykripto:db", "nist-ir-8547:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 3306,
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
                title=f"MySQL connection failed at {self.host}:{self.port}: {e}",
            ))
            return
        try:
            try:
                hdr = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout_s)
            except (TimeoutError, asyncio.IncompleteReadError):
                return
            pkt_len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
            try:
                payload = await asyncio.wait_for(
                    reader.readexactly(pkt_len), timeout=self.timeout_s,
                )
            except (TimeoutError, asyncio.IncompleteReadError):
                return
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if len(payload) < 36 or payload[0] not in (10, 9):
            return
        # protocol_version=1 byte, server_version null-terminated, conn_id 4,
        # auth_plugin_data_part_1 8, filler 1, capability_flags_lower 2.
        try:
            null_idx = payload.index(b"\x00", 1)
        except ValueError:
            return
        server_version = payload[1:null_idx].decode("utf-8", errors="replace")
        rest = payload[null_idx + 1:]
        if len(rest) < 15:
            return
        cap_lower = struct.unpack("<H", rest[12:14])[0]
        cap_upper = 0
        if len(rest) >= 31:
            cap_upper = struct.unpack("<H", rest[27:29])[0]
        capabilities = (cap_upper << 16) | cap_lower
        ssl_ok = bool(capabilities & _CLIENT_SSL_FLAG)
        if ssl_ok:
            emit(Finding(
                probe_id=self.id,
                algorithm="MySQL-CLIENT_SSL",
                classification=Classification.TINGGI,
                severity=Severity.MED,
                title=f"MySQL at {self.host}:{self.port} advertises CLIENT_SSL ({server_version})",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "server_version": server_version,
                          "capabilities_hex": f"0x{capabilities:08x}"},
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="MySQL-NO-SSL",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"MySQL at {self.host}:{self.port} does NOT advertise CLIENT_SSL ({server_version})",
                evidence={"endpoint": f"{self.host}:{self.port}",
                          "server_version": server_version,
                          "capabilities_hex": f"0x{capabilities:08x}"},
                remediation={"snippet": "# Enable TLS in MySQL: require_secure_transport=ON"},
            ))
