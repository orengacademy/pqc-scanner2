"""UDP port scan probe."""
from __future__ import annotations

import asyncio
from typing import Any

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._udp_payloads import DEFAULT_UDP_PORTS, UDPPayload


class NetPortsUDP(Probe):
    id = "net.ports.udp"
    family = ProbeFamily.NETWORK
    framework_tags = ("nacsa-9:port-discovery", "bukukerja:port-discovery")
    requires = frozenset()

    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: list[int] | None = None,
        timeout_s: float = 2.0,
        mode: str = "auto",
    ) -> None:
        self.host = host
        self.ports = ports
        self.timeout_s = timeout_s
        self.mode = mode

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    def _resolve_mode(self, ctx: ScanContext) -> str:
        if self.mode in ("raw", "targeted"):
            return self.mode
        if Capability.NET_RAW in ctx.available_capabilities:
            return "raw"
        return "targeted"

    def _payload_for(self, port: int) -> UDPPayload:
        for p in DEFAULT_UDP_PORTS:
            if p.port == port:
                return p
        return UDPPayload(port=port, name=f"unknown-{port}", payload=b"PROBE", expect_response=True)

    async def _probe_targeted(self, port: int) -> tuple[str, dict[str, Any]]:
        payload = self._payload_for(port)
        loop = asyncio.get_running_loop()
        future_resp: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: Any) -> None:
                if not future_resp.done():
                    future_resp.set_result(data)

            def error_received(self, exc: Exception) -> None:
                if not future_resp.done():
                    future_resp.set_exception(exc)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(self.host, port),
            )
        except OSError as e:
            return "filtered", {"port": port, "error": repr(e), "name": payload.name}

        try:
            transport.sendto(payload.payload)
            if not payload.expect_response:
                return "open|filtered", {"port": port, "name": payload.name, "no_response_expected": True}
            try:
                resp = await asyncio.wait_for(future_resp, timeout=self.timeout_s)
                return "open", {
                    "port": port, "name": payload.name,
                    "response_len": len(resp),
                    "response_head_hex": resp[:32].hex(),
                }
            except TimeoutError:
                return "open|filtered", {"port": port, "name": payload.name, "timeout_s": self.timeout_s}
            except OSError as e:
                return "closed", {"port": port, "name": payload.name, "error": repr(e)}
        finally:
            transport.close()

    async def _probe_raw(self, port: int) -> tuple[str, dict[str, Any]]:
        return await self._probe_targeted(port)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        mode = self._resolve_mode(ctx)
        ports = self.ports or [p.port for p in DEFAULT_UDP_PORTS]

        async def _one(port: int) -> None:
            if mode == "raw":
                state, evidence = await self._probe_raw(port)
            else:
                state, evidence = await self._probe_targeted(port)
            evidence = {"state": state, "mode": mode, **evidence}
            sev = Severity.INFO if state in ("closed", "filtered") else Severity.LOW
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=sev,
                title=f"UDP {self.host}:{port} {state}",
                evidence=evidence,
            ))

        await asyncio.gather(*(_one(p) for p in ports))
