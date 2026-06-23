"""net.tls.kex_groups — enumerate a TLS server's selected key-exchange group.

Phase 2 keystone (docs/COVERAGE-ROADMAP.md). The OS-ssl-based probes only see
the negotiated cipher + leaf cert, never the KEX group, so classical
ECDHE/FFDHE harvest-now-decrypt-later exposure is invisible. This probe speaks
raw TLS 1.3 over a socket (no OS ssl dependency): it sends a ClientHello
offering a broad group set with an EMPTY key_share, which forces the server to
reveal its preferred group in a HelloRetryRequest (or ServerHello) key_share
extension — no key-exchange crypto required.

A classical selected group (X25519/secp*/ffdhe) means the session is
HNDL-exposed; a hybrid (X25519MLKEM768, etc.) means the server can negotiate
post-quantum key exchange.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# group code -> (name, is_pqc_hybrid)
_GROUPS: dict[int, tuple[str, bool]] = {
    0x001D: ("x25519", False),
    0x0017: ("secp256r1", False),
    0x0018: ("secp384r1", False),
    0x0019: ("secp521r1", False),
    0x0100: ("ffdhe2048", False),
    0x0101: ("ffdhe3072", False),
    0x0102: ("ffdhe4096", False),
    0x11EC: ("X25519MLKEM768", True),
    0x11EB: ("SecP256r1MLKEM768", True),
    0x11ED: ("SecP384r1MLKEM1024", True),
    0x6399: ("X25519Kyber768Draft00", True),
    0x639A: ("SecP256r1Kyber768Draft00", True),
}
# Order offered in the ClientHello (hybrids first to express preference).
_OFFER_ORDER = [0x11EC, 0x11EB, 0x6399, 0x001D, 0x0017, 0x0018, 0x0019, 0x0101, 0x0100]

_FIXED_RANDOM = bytes(range(32))  # deterministic; randomness is not security-relevant here


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _vec16(body: bytes) -> bytes:
    return _u16(len(body)) + body


def _extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vec16(body)


def build_client_hello(server_name: str | None = None, *, random: bytes = _FIXED_RANDOM) -> bytes:
    """Build a complete TLS record carrying a TLS 1.3 ClientHello that offers
    the broad group set with an empty key_share."""
    groups = b"".join(_u16(g) for g in _OFFER_ORDER)
    exts = b"".join([
        _extension(0x002B, b"\x02" + b"\x03\x04"),          # supported_versions: TLS 1.3
        _extension(0x000A, _vec16(groups)),                  # supported_groups
        _extension(0x0033, _vec16(b"")),                     # key_share: empty -> forces HRR
        _extension(0x000D, _vec16(                           # signature_algorithms
            _u16(0x0403) + _u16(0x0804) + _u16(0x0401) + _u16(0x0805) + _u16(0x0806)
        )),
    ])
    if server_name:
        host = server_name.encode("idna") if server_name.isascii() else server_name.encode()
        sni = _vec16(b"\x00" + _vec16(host))                 # server_name_list: type host_name
        exts += _extension(0x0000, sni)

    body = (
        b"\x03\x03"                                           # legacy_version TLS 1.2
        + random
        + b"\x00"                                             # legacy_session_id (empty)
        + _vec16(b"\x13\x01\x13\x02\x13\x03")                 # cipher_suites (AES128/256-GCM, CHACHA)
        + b"\x01\x00"                                         # legacy_compression: null
        + _vec16(exts)
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body   # u24 length
    return b"\x16\x03\x01" + _vec16(handshake)               # record: handshake, TLS 1.0


def parse_server_hello(data: bytes) -> dict | None:
    """Parse a TLS handshake response and extract the selected group/version.

    Returns {version, cipher, group_code, group_name, is_pqc} or None if the
    bytes are not a ServerHello / HelloRetryRequest (e.g. an alert)."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    rec_len = struct.unpack(">H", data[3:5])[0]
    hs = data[5:5 + rec_len]
    if len(hs) < 4 or hs[0] != 0x02:                         # ServerHello / HRR
        return None
    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + hs_len]
    try:
        off = 2 + 32                                         # legacy_version + random
        sid_len = body[off]
        off += 1 + sid_len                                   # legacy_session_id
        cipher = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        off += 1                                             # legacy_compression_method
        ext_total = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        exts = body[off:off + ext_total]
    except IndexError:
        return None

    version = 0x0303
    group_code: int | None = None
    i = 0
    while i + 4 <= len(exts):
        et = struct.unpack(">H", exts[i:i + 2])[0]
        el = struct.unpack(">H", exts[i + 2:i + 4])[0]
        ev = exts[i + 4:i + 4 + el]
        i += 4 + el
        if et == 0x002B and len(ev) >= 2:                    # supported_versions (selected)
            version = struct.unpack(">H", ev[:2])[0]
        elif et == 0x0033 and len(ev) >= 2:                  # key_share (selected group)
            group_code = struct.unpack(">H", ev[:2])[0]
    if group_code is None:
        return None
    name, is_pqc = _GROUPS.get(group_code, (f"unknown-0x{group_code:04x}", False))
    return {
        "version": version,
        "cipher": cipher,
        "group_code": group_code,
        "group_name": name,
        "is_pqc": is_pqc,
    }


class NetTlsKexGroups(Probe):
    """Enumerate a TLS server's selected KEX group via a raw handshake."""

    id = "net.tls.kex_groups"
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
        result = await self._handshake(host, port)
        if result is None:
            return

        if result["is_pqc"]:
            emit(Finding(
                probe_id=self.id,
                algorithm=result["group_name"],
                classification=Classification.PQC_READY,
                severity=Severity.INFO,
                title=(f"{host}:{port} negotiates post-quantum hybrid key "
                       f"exchange ({result['group_name']})"),
                evidence={"host": host, "port": port, **_ev(result)},
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm=result["group_name"],
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=(f"{host}:{port} selects classical key exchange "
                       f"({result['group_name']}) — harvest-now-decrypt-later exposed"),
                evidence={
                    "host": host, "port": port, **_ev(result),
                    "note": ("Server chose a classical ECDHE/FFDHE group despite "
                             "being offered hybrid ML-KEM groups; recorded TLS "
                             "traffic is decryptable once a CRQC exists."),
                },
            ))

    async def _handshake(self, host: str, port: int) -> dict | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except (OSError, TimeoutError):
            return None
        try:
            writer.write(build_client_hello(host))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)
        except (OSError, TimeoutError):
            return None
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await writer.wait_closed()
        return parse_server_hello(data)


def _ev(result: dict) -> dict:
    return {
        "group": result["group_name"],
        "group_code": f"0x{result['group_code']:04x}",
        "tls_version": f"0x{result['version']:04x}",
    }
