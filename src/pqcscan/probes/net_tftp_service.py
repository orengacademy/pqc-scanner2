"""net.tftp.service — detect a TFTP service (UDP 69).

TFTP (RFC 1350) has no authentication and no encryption. Like Telnet it sits
at the crypto-posture floor — nothing to be quantum-vulnerable because nothing
is protected — and it is a common firmware/PXE-boot and network-appliance
config transport, so it is worth flagging when present.

Detection sends a Read Request (RRQ) for a benign filename. A live TFTP server
answers with either a DATA packet (opcode 3) or, far more commonly for an
unknown name, an ERROR packet (opcode 5, "File not found"). Any well-formed
TFTP reply confirms the service; we never read or write real files.
"""
from __future__ import annotations

import asyncio
import socket
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_OP_DATA = 3
_OP_ERROR = 5
# RRQ: opcode 1, filename, 0, mode "octet", 0. A read of a name that almost
# certainly does not exist, so a compliant server replies ERROR without serving
# anything.
_RRQ = b"\x00\x01" + b"pqcscan-probe" + b"\x00" + b"octet" + b"\x00"


class NetTftpService(Probe):
    id = "net.tftp.service"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tftp", "mykripto:tftp")

    def __init__(self, host: str = "127.0.0.1", port: int = 69,
                 timeout_s: float = 3.0):
        self.host, self.port, self.timeout_s = host, port, timeout_s

    def _effective_host(self, ctx: ScanContext) -> str:
        if ctx.server_target:
            host = ctx.server_target.partition(":")[0]
            if host:
                return host
        return self.host

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        host = self._effective_host(ctx)
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (host, self.port))
            await loop.sock_sendall(sock, _RRQ)
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 1024), timeout=self.timeout_s,
                )
            except TimeoutError:
                return  # no reply — treat as no TFTP service (silent, no noise)
        except OSError as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"TFTP probe failed at {host}:{self.port}: {e}",
            ))
            return
        finally:
            sock.close()
        if len(data) < 2:
            return
        opcode = struct.unpack(">H", data[:2])[0]
        if opcode not in (_OP_DATA, _OP_ERROR):
            return  # not a TFTP reply — don't guess
        endpoint = f"{host}:{self.port}"
        emit(Finding(
            probe_id=self.id,
            algorithm="cleartext-tftp",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title=f"TFTP service at {endpoint} (no authentication or encryption)",
            evidence={"endpoint": endpoint, "tftp_opcode": opcode,
                      "response_bytes": len(data)},
            remediation={"snippet": "# Replace TFTP with an authenticated, "
                                    "encrypted transport (SFTP/SCP over SSH, "
                                    "or HTTPS) for config/firmware delivery."},
        ))
