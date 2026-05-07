from __future__ import annotations

import asyncio
import socket
from typing import Any

import pytest

from pqcscan.core.types import Finding
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_ports_udp import NetPortsUDP


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def echo_udp_server():
    port = _free_udp_port()
    loop = asyncio.get_running_loop()

    class _EchoProto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport: Any) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Any) -> None:
            if self.transport:
                self.transport.sendto(b"PONG:" + data[:32], addr)

    transport, _ = await loop.create_datagram_endpoint(
        _EchoProto, local_addr=("127.0.0.1", port),
    )
    try:
        yield "127.0.0.1", port
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_targeted_mode_open_port_emits_finding(echo_udp_server):
    host, port = echo_udp_server
    probe = NetPortsUDP(host=host, ports=[port], mode="targeted", timeout_s=1.0)
    findings: list[Finding] = []

    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, findings.append)

    assert len(findings) == 1
    assert findings[0].evidence["state"] == "open"
    assert findings[0].evidence["port"] == port


@pytest.mark.asyncio
async def test_targeted_mode_closed_port_emits_filtered():
    closed_port = _free_udp_port()
    probe = NetPortsUDP(host="127.0.0.1", ports=[closed_port], mode="targeted", timeout_s=0.5)
    findings: list[Finding] = []
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, findings.append)

    assert len(findings) == 1
    assert findings[0].evidence["state"] in {"closed", "filtered", "open|filtered"}
