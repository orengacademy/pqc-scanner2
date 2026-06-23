"""net.tls.versions — raw-socket TLS protocol-version sweep (no OS ssl).

For each TLS/SSL protocol version this probe sends a minimal ClientHello that
negotiates ONLY that version and detects from the reply whether the server
ACCEPTS (handshake record 0x16 carrying a ServerHello, handshake type 0x02) or
REJECTS (alert record 0x15, or a connection reset / timeout).

For versions <= TLS 1.2 the ClientHello legacy_version is set to the target
version code and the supported_versions extension is OMITTED, so a strict
server negotiates exactly that protocol. For TLS 1.3 the legacy_version stays
at 0x0303 and supported_versions=[0x0304] is included (as the RFC requires).

Classifications:
- SSL 3.0 / TLS 1.0 accepted  -> TINGGI/HIGH  (broken/deprecated transport)
- TLS 1.1 accepted            -> SEDERHANA/MED
- TLS 1.3 NOT supported       -> SEDERHANA/MED (no PQC-capable transport —
                                 TLS 1.3 is required for hybrid ML-KEM KEX)
- TLS 1.3 supported           -> INFO
"""
from __future__ import annotations

import asyncio
import contextlib
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# version code -> human-readable name
_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}
# Sweep order (oldest first).
_SWEEP_ORDER = [0x0300, 0x0301, 0x0302, 0x0303, 0x0304]

_FIXED_RANDOM = bytes(range(32))  # deterministic; randomness is not security-relevant here


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _vec16(body: bytes) -> bytes:
    return _u16(len(body)) + body


def _extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vec16(body)


def build_client_hello(version: int, server_name: str | None = None,
                       *, random: bytes = _FIXED_RANDOM) -> bytes:
    """Build a TLS record carrying a ClientHello that negotiates ONLY `version`.

    For version <= 0x0303 the legacy_version field carries `version` and no
    supported_versions extension is sent. For 0x0304 (TLS 1.3) the legacy_version
    is 0x0303 and supported_versions=[0x0304] is included."""
    is_tls13 = version >= 0x0304
    legacy_version = 0x0303 if is_tls13 else version

    exts = b""
    if is_tls13:
        exts += _extension(0x002B, b"\x02" + b"\x03\x04")        # supported_versions: TLS 1.3
    exts += _extension(0x000A, _vec16(                           # supported_groups
        _u16(0x001D) + _u16(0x0017) + _u16(0x0018) + _u16(0x11EC)
    ))
    exts += _extension(0x000D, _vec16(                          # signature_algorithms
        _u16(0x0403) + _u16(0x0804) + _u16(0x0401) + _u16(0x0805) + _u16(0x0806)
    ))
    if is_tls13:
        exts += _extension(0x0033, _vec16(b""))                 # key_share: empty
    if server_name:
        host = server_name.encode("idna") if server_name.isascii() else server_name.encode()
        sni = _vec16(b"\x00" + _vec16(host))                    # server_name_list: type host_name
        exts += _extension(0x0000, sni)

    body = (
        _u16(legacy_version)                                    # legacy_version
        + random
        + b"\x00"                                               # legacy_session_id (empty)
        + _vec16(b"\x13\x01\x13\x02\x13\x03"                    # cipher_suites: TLS 1.3 suites
                 + b"\xc0\x2f\xc0\x30\x00\x9c\x00\x35\x00\x0a")  #   + classical (RSA/ECDHE)
        + b"\x01\x00"                                           # legacy_compression: null
        + _vec16(exts)
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body   # u24 length
    return b"\x16\x03\x01" + _vec16(handshake)                  # record: handshake, TLS 1.0


def detect_accept(data: bytes) -> bool:
    """True if `data` is a TLS handshake record (0x16) carrying a ServerHello
    (handshake type 0x02) — i.e. the server ACCEPTED the offered version.

    An alert record (0x15), empty bytes, or any non-ServerHello reply is treated
    as a REJECT."""
    if len(data) < 6 or data[0] != 0x16:
        return False
    rec_len = struct.unpack(">H", data[3:5])[0]
    hs = data[5:5 + rec_len]
    return len(hs) >= 1 and hs[0] == 0x02


class NetTlsVersions(Probe):
    """Raw-socket TLS version sweep: which protocols a server still accepts."""

    id = "net.tls.versions"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "cnsa2:tls", "nacsa-9:pqc-readiness")

    def __init__(self, target: str | None = None, timeout: float = 6.0):
        self.target = target
        self.timeout = timeout

    def _resolve_target(self, ctx: ScanContext) -> tuple[str, int] | None:
        raw = self.target or ctx.server_target
        if not raw:
            return None
        host, _, port = raw.partition(":")
        if not host:
            return None
        if not port:
            return host, 443
        try:
            return host, int(port)
        except ValueError:
            return None

    async def applies(self, ctx: ScanContext) -> bool:
        return self._resolve_target(ctx) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        tgt = self._resolve_target(ctx)
        if tgt is None:
            return
        host, port = tgt

        accepted: dict[int, bool] = {}
        for version in _SWEEP_ORDER:
            accepted[version] = await self._probe_version(host, port, version)

        for version in _SWEEP_ORDER:
            if version == 0x0304 or not accepted[version]:
                continue
            name = _VERSIONS[version]
            if version in (0x0300, 0x0301):
                emit(Finding(
                    probe_id=self.id,
                    algorithm=name,
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"{host}:{port} accepts {name} (broken/deprecated TLS version)",
                    evidence={"host": host, "port": port, "version": name,
                              "version_code": f"0x{version:04x}"},
                    remediation={"snippet": f"# Disable {name} on the server (require TLS 1.2+)"},
                ))
            elif version == 0x0302:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=name,
                    classification=Classification.SEDERHANA,
                    severity=Severity.MED,
                    title=f"{host}:{port} accepts {name} (deprecated TLS version)",
                    evidence={"host": host, "port": port, "version": name,
                              "version_code": f"0x{version:04x}"},
                    remediation={"snippet": f"# Disable {name} on the server (require TLS 1.2+)"},
                ))

        if accepted[0x0304]:
            emit(Finding(
                probe_id=self.id,
                algorithm="TLS 1.3",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"{host}:{port} supports TLS 1.3 (PQC-capable transport available)",
                evidence={"host": host, "port": port, "version": "TLS 1.3",
                          "version_code": "0x0304"},
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="TLS 1.3",
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=(f"{host}:{port} does not support TLS 1.3 — "
                       f"no PQC-capable transport"),
                evidence={
                    "host": host, "port": port,
                    "supported": [_VERSIONS[v] for v in _SWEEP_ORDER if accepted[v]],
                    "note": ("TLS 1.3 is required for hybrid ML-KEM key exchange; a "
                             "TLS-1.2-only server cannot negotiate post-quantum KEX."),
                },
            ))

    async def _probe_version(self, host: str, port: int, version: int) -> bool:
        """Open a connection, send a version-specific ClientHello, return True if
        the server accepts (ServerHello), False on alert/reset/timeout."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except (OSError, TimeoutError):
            return False
        try:
            writer.write(build_client_hello(version, host))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)
        except (OSError, TimeoutError):
            return False
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await writer.wait_closed()
        return detect_accept(data)
