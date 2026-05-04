"""net.ike.v1v2 — UDP 500 ISAKMP detection (IKEv1 / IKEv2)."""
from __future__ import annotations

import asyncio
import os
import socket
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


# IKEv2 IKE_SA_INIT header (28 bytes ISAKMP) — minimal probe.
def _ikev2_init() -> bytes:
    initiator_cookie = os.urandom(8)
    responder_cookie = b"\x00" * 8
    next_payload = 33  # SA
    version = (2 << 4) | 0  # major=2 minor=0 -> 0x20
    exchange = 34  # IKE_SA_INIT
    flags = 0x08  # initiator
    msgid = 0
    # Just the header — many real IKEv2 stacks reply with a NO_PROPOSAL_CHOSEN
    # error, which is enough to confirm IKE is listening.
    length = 28
    return struct.pack(
        ">8s8sBBBBII",
        initiator_cookie, responder_cookie,
        next_payload, version, exchange, flags, msgid, length,
    )


class NetIkeV1V2(Probe):
    id = "net.ike.v1v2"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:vpn", "bukukerja:vpn", "mykripto:vpn")

    def __init__(self, host: str = "127.0.0.1", port: int = 500,
                 timeout_s: float = 3.0):
        self.host, self.port, self.timeout_s = host, port, timeout_s

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (self.host, self.port))
            await loop.sock_sendall(sock, _ikev2_init())
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 4096),
                                               timeout=self.timeout_s)
            except asyncio.TimeoutError:
                emit(Finding(
                    probe_id=self.id, algorithm="N/A",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"IKE UDP {self.host}:{self.port} silent (no response)",
                ))
                return
        except (OSError, asyncio.TimeoutError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"IKE probe failed at {self.host}:{self.port}: {e}",
            ))
            return
        finally:
            sock.close()
        if len(data) < 28:
            return
        # ISAKMP header: byte 17 = version (high nibble = major).
        version = data[17]
        major = version >> 4
        emit(Finding(
            probe_id=self.id,
            algorithm=f"IKEv{major}",
            classification=Classification.TINGGI,  # all classical IKE -> Shor-vulnerable
            severity=Severity.HIGH,
            title=f"IKE responder version {major} at {self.host}:{self.port}",
            evidence={"endpoint": f"{self.host}:{self.port}",
                      "isakmp_version_byte": version,
                      "response_bytes": len(data)},
        ))
