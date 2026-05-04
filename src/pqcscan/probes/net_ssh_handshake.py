"""net.ssh.handshake — TCP-connect, parse SSH-2.0 banner + SSH_MSG_KEXINIT.

KEXINIT (msg type 20) carries six namelists: kex_algorithms, server_host_key
algorithms, encryption client->server, encryption server->client, MAC
client->server, MAC server->client. Each is comma-separated UTF-8.
"""
from __future__ import annotations

import asyncio
import struct

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for
from pqcscan.probes._ssh_parser import SSH_ALG_ALIASES


_BANNER = b"SSH-2.0-pqcscan_1.0\r\n"


class NetSshHandshake(Probe):
    id = "net.ssh.handshake"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:ssh", "bukukerja:ssh", "mykripto:ssh")

    def __init__(self, host: str = "127.0.0.1", port: int = 22,
                 timeout_s: float = 10.0):
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
                title=f"SSH connection failed at {self.host}:{self.port}: {e}",
            ))
            return
        try:
            # 1. Read peer banner ("SSH-2.0-OpenSSH_x.y\r\n").
            try:
                banner = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return
            # 2. Send our banner.
            writer.write(_BANNER); await writer.drain()
            # 3. Read packets until we get SSH_MSG_KEXINIT (msg type 20).
            kexinit = await self._read_until_kexinit(reader)
            if kexinit is None:
                return
            self._emit_namelists(kexinit, emit, banner)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _read_until_kexinit(self, reader: asyncio.StreamReader,
                                   max_packets: int = 5) -> bytes | None:
        for _ in range(max_packets):
            try:
                hdr = await asyncio.wait_for(reader.readexactly(5), timeout=5.0)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return None
            pkt_len = struct.unpack(">I", hdr[:4])[0]
            pad_len = hdr[4]
            try:
                rest = await asyncio.wait_for(
                    reader.readexactly(pkt_len - 1), timeout=5.0,
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return None
            payload = rest[: pkt_len - 1 - pad_len]
            if not payload:
                continue
            if payload[0] == 20:  # SSH_MSG_KEXINIT
                return payload
        return None

    def _emit_namelists(self, payload: bytes, emit: Emitter, banner: bytes) -> None:
        # Skip msg type (1 byte) + cookie (16 bytes).
        i = 17
        labels = [
            "kex_algorithms", "server_host_key_algorithms",
            "encryption_c2s", "encryption_s2c",
            "mac_c2s", "mac_s2c",
            "compression_c2s", "compression_s2c",
            "languages_c2s", "languages_s2c",
        ]
        emit(Finding(
            probe_id=self.id, algorithm="N/A",
            classification=Classification.INFO, severity=Severity.INFO,
            title=f"SSH banner: {banner.decode('ascii', errors='replace').strip()}",
            evidence={"endpoint": f"{self.host}:{self.port}",
                      "banner": banner.decode('ascii', errors='replace').strip()},
        ))
        for label in labels:
            if i + 4 > len(payload):
                return
            ln = struct.unpack(">I", payload[i:i + 4])[0]
            i += 4
            value = payload[i:i + ln].decode("utf-8", errors="replace")
            i += ln
            for token in value.split(","):
                token = token.strip()
                if not token:
                    continue
                canonical = SSH_ALG_ALIASES.get(token, normalise(token))
                cls = classify(canonical)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id, algorithm=canonical,
                        classification=cls, severity=sev_for(cls),
                        title=f"SSH server offers {label}={token}",
                        evidence={"endpoint": f"{self.host}:{self.port}",
                                  "namelist": label, "token": token},
                    ))
