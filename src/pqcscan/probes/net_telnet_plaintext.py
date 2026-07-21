"""net.telnet.plaintext — detect a cleartext Telnet service (TCP 23).

Telnet transmits everything — credentials included — with no transport
encryption whatsoever. For a crypto-posture scan that is the floor: there is
no cipher to be quantum-vulnerable because there is no cipher at all. A live
Telnet server therefore warrants the top classification.

Detection is a passive read of the server's opening bytes: an RFC 854 Telnet
daemon immediately sends IAC (0xFF) option-negotiation commands. Seeing IAC
confirms Telnet; a non-IAC banner on :23 is still a cleartext service but is
reported one band lower to stay honest about the weaker signal.
"""
from __future__ import annotations

import asyncio
import contextlib

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_IAC = 0xFF  # RFC 854 "Interpret As Command" — begins every Telnet negotiation.


class NetTelnetPlaintext(Probe):
    id = "net.telnet.plaintext"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:telnet", "mykripto:telnet")

    def __init__(self, host: str = "127.0.0.1", port: int = 23,
                 timeout_s: float = 5.0):
        self.host, self.port, self.timeout_s = host, port, timeout_s

    def _effective_host(self, ctx: ScanContext) -> str:
        # Default to localhost like the other host-service probes, but let an
        # explicit --target (ctx.server_target, "host[:port]") redirect us.
        if ctx.server_target:
            host = ctx.server_target.partition(":")[0]
            if host:
                return host
        return self.host

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        host = self._effective_host(ctx)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, self.port),
                timeout=self.timeout_s,
            )
        except (TimeoutError, OSError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"Telnet connection failed at {host}:{self.port}: {e}",
            ))
            return
        try:
            try:
                data = await asyncio.wait_for(reader.read(64), timeout=self.timeout_s)
            except TimeoutError:
                return  # open but silent — not enough signal to classify
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if not data:
            return
        endpoint = f"{host}:{self.port}"
        remediation = {"snippet": "# Disable telnetd; use SSH (OpenSSH) for "
                                  "remote administration instead."}
        if data[0] == _IAC:
            emit(Finding(
                probe_id=self.id,
                algorithm="cleartext-telnet",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"Cleartext Telnet service at {endpoint} "
                      "(no transport encryption)",
                evidence={"endpoint": endpoint, "iac_negotiation": True,
                          "response_bytes": len(data)},
                remediation=remediation,
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="cleartext-service",
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=f"Cleartext service (no TLS) responding on {endpoint}",
                evidence={"endpoint": endpoint, "iac_negotiation": False,
                          "response_bytes": len(data)},
                remediation=remediation,
            ))
