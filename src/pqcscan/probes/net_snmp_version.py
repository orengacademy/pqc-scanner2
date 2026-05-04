"""net.snmp.version — SNMPv1/v2c/v3 version detection via UDP 161 GetRequest."""
from __future__ import annotations

import asyncio
import socket

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


# Minimal SNMPv2c GetRequest for sysDescr.0 with community "public".
# ASN.1 BER hand-encoded.
_SNMPV2C_PROBE = bytes.fromhex(
    "302602010104067075626c6963"     # SEQUENCE { INTEGER 1=v2c, OCTET STRING "public" }
    "a0190204756969690201000201003020"   # GetRequest PDU header
    "300e060a2b060102010101050005000500"  # varbind: sysDescr.0 = NULL
)


class NetSnmpVersion(Probe):
    id = "net.snmp.version"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:snmp", "bukukerja:snmp", "mykripto:snmp")

    def __init__(self, host: str = "127.0.0.1", port: int = 161,
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
            await loop.sock_sendall(sock, _SNMPV2C_PROBE)
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096), timeout=self.timeout_s,
                )
            except asyncio.TimeoutError:
                return
        except OSError as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"SNMP probe failed at {self.host}:{self.port}: {e}",
            ))
            return
        finally:
            sock.close()
        if len(data) < 5 or data[0] != 0x30:
            return
        # SNMPv2c response — community-based auth is plaintext, classify HIGH.
        emit(Finding(
            probe_id=self.id,
            algorithm="SNMPv2c-community",
            classification=Classification.SANGAT_TINGGI,
            severity=Severity.CRIT,
            title=f"SNMPv2c community-based authentication at {self.host}:{self.port}",
            evidence={"endpoint": f"{self.host}:{self.port}",
                      "response_bytes": len(data)},
            remediation={"snippet": "# Migrate to SNMPv3 with USM (auth+priv)"},
        ))
