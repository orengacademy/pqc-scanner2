"""net.db.mssql_tls — SQL Server TDS PRELOGIN + TLS-in-TDS probe.

SQL Server does not speak TLS on the wire directly: the TLS handshake is
tunnelled inside TDS ``PRELOGIN`` packets (MS-TDS §2.2.6.5). This probe

  1. sends a PRELOGIN offering ENCRYPT_ON to make the server reveal its
     encryption stance (off / on / not-supported / required), then
  2. if the server encrypts, tunnels a raw TLS 1.3 ClientHello (empty
     key_share, hybrid groups first) through TDS to read the *selected* KEX
     group — the same HelloRetryRequest trick ``net.tls.kex_groups`` uses,
     which the OS ``ssl`` stack cannot expose.

This closes the SQL-Server-in-transit gap the Postgres/MySQL TLS probes left
open (relevant wherever MyTTx-style SQL Server 2017 back-ends are in scope).
Pure ``struct``; no pyodbc / TDS driver dependency. Never raises out of run().
"""
from __future__ import annotations

import asyncio
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes.net_tls_kex_groups import build_client_hello, parse_server_hello

# TDS packet types (MS-TDS §2.2.3.1.1).
_TDS_PRELOGIN = 0x12
_TDS_STATUS_EOM = 0x01

# PRELOGIN option tokens (MS-TDS §2.2.6.5).
_OPT_VERSION = 0x00
_OPT_ENCRYPTION = 0x01
_OPT_TERMINATOR = 0xFF

# ENCRYPTION option values.
ENCRYPT_OFF = 0x00       # encryption available, not used unless client insists
ENCRYPT_ON = 0x01        # encryption available and used
ENCRYPT_NOT_SUP = 0x02   # server cannot encrypt — login travels in cleartext
ENCRYPT_REQ = 0x03       # server requires encryption

_ENCRYPT_LABEL = {
    ENCRYPT_OFF: "ENCRYPT_OFF (optional)",
    ENCRYPT_ON: "ENCRYPT_ON",
    ENCRYPT_NOT_SUP: "ENCRYPT_NOT_SUP (plaintext only)",
    ENCRYPT_REQ: "ENCRYPT_REQ (required)",
}


def wrap_tds(payload: bytes, *, packet_type: int = _TDS_PRELOGIN) -> bytes:
    """Wrap a payload in an 8-byte TDS packet header (single, final packet)."""
    length = len(payload) + 8
    return struct.pack(">BBHHBB", packet_type, _TDS_STATUS_EOM, length, 0, 1, 0) + payload


def unwrap_tds(packet: bytes) -> bytes | None:
    """Return the payload of a single TDS packet, or None if malformed."""
    if len(packet) < 8:
        return None
    length = struct.unpack(">H", packet[2:4])[0]
    if length < 8 or length > len(packet):
        return None
    return packet[8:length]


def build_prelogin() -> bytes:
    """A PRELOGIN packet advertising VERSION and ENCRYPT_ON.

    Offering ENCRYPT_ON (rather than ENCRYPT_NOT_SUP) makes the server answer
    with its real stance instead of short-circuiting to plaintext."""
    # Option table entries are (token, offset, length); offsets are relative
    # to the start of the option data (after the terminator).
    version_data = b"\x10\x00\x0b\xe2\x00\x00"   # 16.0.11234, build 0
    encryption_data = bytes([ENCRYPT_ON])
    header_len = 5 + 5 + 1                        # two options + terminator
    off_version = header_len
    off_encryption = off_version + len(version_data)
    table = (
        bytes([_OPT_VERSION]) + struct.pack(">HH", off_version, len(version_data))
        + bytes([_OPT_ENCRYPTION]) + struct.pack(">HH", off_encryption, len(encryption_data))
        + bytes([_OPT_TERMINATOR])
    )
    return wrap_tds(table + version_data + encryption_data)


def parse_prelogin_response(payload: bytes) -> dict | None:
    """Extract the ENCRYPTION stance from a PRELOGIN response payload.

    Walks the option table until the terminator, then reads the ENCRYPTION
    option's single byte. Returns {"encryption": int} or None if absent /
    malformed. Never raises."""
    try:
        i = 0
        options: dict[int, tuple[int, int]] = {}
        while i < len(payload):
            token = payload[i]
            if token == _OPT_TERMINATOR:
                break
            if i + 5 > len(payload):
                return None
            offset, length = struct.unpack(">HH", payload[i + 1:i + 5])
            options[token] = (offset, length)
            i += 5
        if _OPT_ENCRYPTION not in options:
            return None
        offset, length = options[_OPT_ENCRYPTION]
        if length < 1 or offset >= len(payload):
            return None
        return {"encryption": payload[offset]}
    except (IndexError, struct.error):
        return None


class NetDbMssqlTls(Probe):
    id = "net.db.mssql_tls"
    family = ProbeFamily.NETWORK
    framework_tags = (
        "bukukerja:db", "mykripto:db", "nist-ir-8547:tls", "pci-dss-4:tls",
    )

    def __init__(self, host: str | None = None, port: int = 1433, timeout: float = 6.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _resolve_target(self, ctx: ScanContext) -> tuple[str, int]:
        """Explicit constructor host wins; else --target's host on the TDS
        port (its port belongs to the primary TLS service, not SQL Server);
        else localhost:1433."""
        if self.host:
            return self.host, self.port
        if ctx.server_target:
            host, _, _ = ctx.server_target.partition(":")
            if host:
                return host, self.port
        return "127.0.0.1", self.port

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        host, port = self._resolve_target(ctx)
        endpoint = f"{host}:{port}"
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout,
            )
        except (TimeoutError, OSError) as e:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"SQL Server connection failed at {endpoint}: {e}",
                evidence={"endpoint": endpoint},
            ))
            return

        try:
            writer.write(build_prelogin())
            await writer.drain()
            resp = await self._read_tds(reader)
            parsed = parse_prelogin_response(resp) if resp is not None else None
            if parsed is None:
                emit(Finding(
                    probe_id=self.id, algorithm="N/A",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"SQL Server at {endpoint} gave no readable PRELOGIN response",
                    evidence={"endpoint": endpoint},
                ))
                return

            encryption = parsed["encryption"]
            label = _ENCRYPT_LABEL.get(encryption, f"unknown({encryption})")

            if encryption == ENCRYPT_NOT_SUP:
                emit(Finding(
                    probe_id=self.id, algorithm="PLAINTEXT",
                    classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT,
                    title=f"SQL Server at {endpoint} does not support TLS (login in cleartext)",
                    evidence={"endpoint": endpoint, "encryption": label, "verified": True},
                    remediation={"snippet": "Enable Force Encryption in SQL Server "
                                            "Configuration Manager and install a TLS cert."},
                ))
                return

            if encryption == ENCRYPT_OFF:
                emit(Finding(
                    probe_id=self.id, algorithm="TLS-OPTIONAL",
                    classification=Classification.TINGGI, severity=Severity.HIGH,
                    title=f"SQL Server at {endpoint} makes TLS optional (downgradable)",
                    evidence={"endpoint": endpoint, "encryption": label, "verified": True},
                    remediation={"snippet": "Set Force Encryption = Yes so clients "
                                            "cannot negotiate plaintext."},
                ))
                # An optional-TLS server still completes a handshake; fall
                # through to read the group so posture is captured too.

            # Tunnel a raw TLS ClientHello inside TDS PRELOGIN packets.
            hello = build_client_hello(server_name=host if not _is_ip(host) else None)
            writer.write(wrap_tds(hello))
            await writer.drain()
            sh_payload = await self._read_tds(reader)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # pragma: no cover - best-effort close
                pass

        parsed_sh = parse_server_hello(sh_payload) if sh_payload else None
        if parsed_sh is None:
            emit(Finding(
                probe_id=self.id, algorithm="TLS",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"SQL Server at {endpoint} encrypts ({label}); selected group unread",
                evidence={"endpoint": endpoint, "encryption": label},
            ))
            return

        name = parsed_sh["group_name"]
        if parsed_sh["is_pqc"]:
            emit(Finding(
                probe_id=self.id, algorithm=name,
                classification=Classification.PQC_READY, severity=Severity.INFO,
                title=f"SQL Server at {endpoint} negotiated PQC-hybrid group {name}",
                evidence={"endpoint": endpoint, "group": name, "verified": True},
            ))
        else:
            emit(Finding(
                probe_id=self.id, algorithm=name,
                classification=Classification.SEDERHANA, severity=Severity.MED,
                title=f"SQL Server at {endpoint} negotiated classical group {name}",
                evidence={"endpoint": endpoint, "group": name, "verified": True,
                          "hndl": True,
                          "note": "TDS key exchange is harvest-now-decrypt-later exposed; "
                                  "move to a hybrid ML-KEM group."},
            ))

    async def _read_tds(self, reader: asyncio.StreamReader) -> bytes | None:
        """Read one TDS packet and return its payload, or None."""
        try:
            header = await asyncio.wait_for(reader.readexactly(8), timeout=self.timeout)
            length = struct.unpack(">H", header[2:4])[0]
            if length < 8:
                return None
            body = await asyncio.wait_for(
                reader.readexactly(length - 8), timeout=self.timeout,
            )
            return body
        except (TimeoutError, asyncio.IncompleteReadError, struct.error):
            return None


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
