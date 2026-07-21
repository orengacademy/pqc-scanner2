"""Pure-Python pcap / pcapng reader + minimal TLS/SSH handshake extractors.

No scapy / dpkt / pyshark: the frozen binary must stay small, self-contained,
and any-OS, so this hand-rolls just enough of the capture-file and wire formats
to pull the negotiated crypto out of an offline packet capture.

Everything here is defensive: truncated or garbage input yields None / stops
iterating — it never raises. Callers wrap the whole thing in try/except anyway.

Supported capture containers:
- classic pcap        (magic 0xa1b2c3d4 / 0xd4c3b2a1, us + ns timestamp variants)
- pcapng              (Section Header 0x0A0D0D0A, Interface/Enhanced/Simple blocks)

Supported link/L3/L4 stack: Ethernet (+ 802.1Q VLAN), Linux SLL, raw IP →
IPv4 / IPv6 → TCP / UDP → application payload.
"""
from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass

# --- capture-file iteration ---------------------------------------------

_PCAP_MAGIC_BE = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")  # us, ns timestamps
_PCAP_MAGIC_LE = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"  # byte-order independent (palindromic)


def iter_packets(data: bytes) -> Iterator[tuple[bytes, int]]:
    """Yield (link-layer frame bytes, link-layer type) for every packet.

    Auto-detects classic pcap vs pcapng vs neither. Unknown / truncated input
    simply yields nothing instead of raising.
    """
    if len(data) < 4:
        return
    magic = data[:4]
    if magic in _PCAP_MAGIC_BE:
        yield from _iter_classic(data, ">")
    elif magic in _PCAP_MAGIC_LE:
        yield from _iter_classic(data, "<")
    elif magic == _PCAPNG_SHB:
        yield from _iter_pcapng(data)


def _iter_classic(data: bytes, endian: str) -> Iterator[tuple[bytes, int]]:
    if len(data) < 24:
        return
    try:
        linktype = struct.unpack(endian + "I", data[20:24])[0]
    except struct.error:
        return
    pos = 24
    while pos + 16 <= len(data):
        try:
            incl_len = struct.unpack(endian + "I", data[pos + 8:pos + 12])[0]
        except struct.error:
            return
        pos += 16
        if incl_len == 0 or pos + incl_len > len(data):
            return
        yield data[pos:pos + incl_len], linktype
        pos += incl_len


def _iter_pcapng(data: bytes) -> Iterator[tuple[bytes, int]]:
    endian = "<"
    iface_lts: list[int] = []
    pos = 0
    while pos + 12 <= len(data):
        block_type_raw = data[pos:pos + 4]
        try:
            if block_type_raw == _PCAPNG_SHB:
                bom = data[pos + 8:pos + 12]
                if bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                else:
                    return
                iface_lts = []
                total_len = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
            else:
                total_len = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
                block_type = struct.unpack(endian + "I", block_type_raw)[0]
                if pos + total_len <= len(data):
                    body = data[pos + 8:pos + total_len - 4]
                    pkt = _pcapng_block(block_type, body, iface_lts, endian)
                    if pkt is not None:
                        yield pkt
        except (struct.error, IndexError):
            return
        if total_len < 12 or pos + total_len > len(data):
            return
        pos += total_len


def _pcapng_block(
    block_type: int, body: bytes, iface_lts: list[int], endian: str,
) -> tuple[bytes, int] | None:
    if block_type == 0x00000001:  # Interface Description Block
        if len(body) >= 2:
            iface_lts.append(struct.unpack(endian + "H", body[0:2])[0])
        return None
    if block_type == 0x00000006:  # Enhanced Packet Block
        if len(body) < 20:
            return None
        iface_id = struct.unpack(endian + "I", body[0:4])[0]
        caplen = struct.unpack(endian + "I", body[12:16])[0]
        pkt = body[20:20 + caplen]
        lt = iface_lts[iface_id] if iface_id < len(iface_lts) else 1
        return pkt, lt
    if block_type == 0x00000003:  # Simple Packet Block
        if len(body) < 4:
            return None
        origlen = struct.unpack(endian + "I", body[0:4])[0]
        pkt = body[4:4 + origlen]
        lt = iface_lts[0] if iface_lts else 1
        return pkt, lt
    return None


# --- link / network / transport decoding --------------------------------

@dataclass(slots=True)
class Segment:
    """A decoded TCP/UDP segment with its endpoints and application payload."""

    proto: str  # "tcp" | "udp"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes
    seq: int = 0  # TCP sequence number (0 for UDP); used for stream reassembly

    @property
    def src(self) -> str:
        return f"{self.src_ip}:{self.src_port}"

    @property
    def dst(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"


def decode_packet(frame: bytes, linktype: int) -> Segment | None:
    """Decode one link-layer frame down to a TCP/UDP Segment, or None."""
    try:
        if linktype == 1:  # Ethernet
            return _decode_ethernet(frame)
        if linktype == 113:  # Linux "cooked" capture (SLL)
            if len(frame) < 16:
                return None
            eth_type = struct.unpack(">H", frame[14:16])[0]
            return _decode_l3(frame[16:], eth_type)
        if linktype in (101, 12, 14):  # raw IP
            if not frame:
                return None
            version = frame[0] >> 4
            if version == 4:
                return _decode_ipv4(frame)
            if version == 6:
                return _decode_ipv6(frame)
            return None
        return None
    except (struct.error, IndexError, ValueError, OSError):
        return None


def _decode_ethernet(frame: bytes) -> Segment | None:
    if len(frame) < 14:
        return None
    eth_type = struct.unpack(">H", frame[12:14])[0]
    off = 14
    while eth_type in (0x8100, 0x88A8):  # 802.1Q / 802.1ad VLAN tags
        if len(frame) < off + 4:
            return None
        eth_type = struct.unpack(">H", frame[off + 2:off + 4])[0]
        off += 4
    return _decode_l3(frame[off:], eth_type)


def _decode_l3(data: bytes, eth_type: int) -> Segment | None:
    if eth_type == 0x0800:
        return _decode_ipv4(data)
    if eth_type == 0x86DD:
        return _decode_ipv6(data)
    return None


def _decode_ipv4(data: bytes) -> Segment | None:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    total_len = struct.unpack(">H", data[2:4])[0]
    src = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst = socket.inet_ntop(socket.AF_INET, data[16:20])
    payload = data[ihl:total_len] if ihl < total_len <= len(data) else data[ihl:]
    return _decode_l4(proto, src, dst, payload)


def _decode_ipv6(data: bytes) -> Segment | None:
    if len(data) < 40:
        return None
    next_hdr = data[6]
    plen = struct.unpack(">H", data[4:6])[0]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    payload = data[40:40 + plen] if plen else data[40:]
    return _decode_l4(next_hdr, src, dst, payload)


def _decode_l4(proto: int, src: str, dst: str, payload: bytes) -> Segment | None:
    if proto == 6:  # TCP
        if len(payload) < 20:
            return None
        sport, dport = struct.unpack(">HH", payload[0:4])
        seq = struct.unpack(">I", payload[4:8])[0]
        data_off = (payload[12] >> 4) * 4
        if data_off < 20 or len(payload) < data_off:
            return None
        return Segment("tcp", src, sport, dst, dport, payload[data_off:], seq=seq)
    if proto == 17:  # UDP
        if len(payload) < 8:
            return None
        sport, dport = struct.unpack(">HH", payload[0:4])
        return Segment("udp", src, sport, dst, dport, payload[8:])
    return None


# --- TLS handshake extraction -------------------------------------------

def parse_tls_handshake(payload: bytes) -> dict | None:
    """Extract ClientHello / ServerHello fields from a TCP payload.

    ClientHello -> {"type": "client_hello", "legacy_version", "cipher_suites"
    (list[int]), "versions" (list[int]), "groups" (list[int])}.
    ServerHello -> {"type": "server_hello", "legacy_version", "cipher" (int),
    "selected_version" (int|None), "group" (int|None)}.
    Anything else / malformed -> None.
    """
    try:
        if len(payload) < 9 or payload[0] != 0x16:  # TLS handshake record
            return None
        rec_len = struct.unpack(">H", payload[3:5])[0]
        hs = payload[5:5 + rec_len]
        if len(hs) < 4:
            return None
        msg_type = hs[0]
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4:4 + hs_len]
        if msg_type == 0x01:
            return _parse_client_hello(body)
        if msg_type == 0x02:
            return _parse_server_hello(body)
        return None
    except (struct.error, IndexError):
        return None


def _parse_client_hello(body: bytes) -> dict | None:
    off = 2 + 32  # legacy_version + random
    if len(body) < off + 1:
        return None
    legacy_version = struct.unpack(">H", body[0:2])[0]
    sid_len = body[off]
    off += 1 + sid_len
    if len(body) < off + 2:
        return None
    cs_len = struct.unpack(">H", body[off:off + 2])[0]
    off += 2
    cs_raw = body[off:off + cs_len]
    off += cs_len
    ciphers = [struct.unpack(">H", cs_raw[i:i + 2])[0] for i in range(0, len(cs_raw) - 1, 2)]
    if len(body) < off + 1:
        return {"type": "client_hello", "legacy_version": legacy_version,
                "cipher_suites": ciphers, "versions": [], "groups": [],
                "key_share_groups": []}
    comp_len = body[off]
    off += 1 + comp_len
    versions: list[int] = []
    supported_groups: list[int] = []
    key_share_groups: list[int] = []
    if len(body) >= off + 2:
        ext_total = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        versions, supported_groups, key_share_groups = _parse_client_extensions(
            body[off:off + ext_total])
    # "groups" stays the order-preserving, deduped union (supported_groups
    # first, then any key_share-only group) for backward compatibility;
    # "key_share_groups" is the subset for which the client actually sent a
    # key_share — a stronger "actively negotiating this group" signal than a
    # bare supported_groups listing.
    groups = list(dict.fromkeys(supported_groups + key_share_groups))
    return {"type": "client_hello", "legacy_version": legacy_version,
            "cipher_suites": ciphers, "versions": versions, "groups": groups,
            "key_share_groups": key_share_groups}


def _parse_client_extensions(exts: bytes) -> tuple[list[int], list[int], list[int]]:
    versions: list[int] = []
    supported_groups: list[int] = []
    key_share_groups: list[int] = []
    i = 0
    while i + 4 <= len(exts):
        et = struct.unpack(">H", exts[i:i + 2])[0]
        el = struct.unpack(">H", exts[i + 2:i + 4])[0]
        ev = exts[i + 4:i + 4 + el]
        i += 4 + el
        if et == 0x002B and ev:  # supported_versions: 1-byte list length + u16 versions
            n = ev[0]
            versions = [struct.unpack(">H", ev[1 + j:3 + j])[0] for j in range(0, n - 1, 2)]
        elif et == 0x000A and len(ev) >= 2:  # supported_groups: u16 list length + u16 groups
            n = struct.unpack(">H", ev[0:2])[0]
            gv = ev[2:2 + n]
            supported_groups += [struct.unpack(">H", gv[j:j + 2])[0]
                                 for j in range(0, len(gv) - 1, 2)]
        elif et == 0x0033 and len(ev) >= 2:  # key_share: u16 list length + entries
            n = struct.unpack(">H", ev[0:2])[0]
            key_share_groups += _parse_key_share_groups(ev[2:2 + n])
    return versions, supported_groups, key_share_groups


def _parse_key_share_groups(entries: bytes) -> list[int]:
    out: list[int] = []
    j = 0
    while j + 4 <= len(entries):
        group = struct.unpack(">H", entries[j:j + 2])[0]
        klen = struct.unpack(">H", entries[j + 2:j + 4])[0]
        out.append(group)
        j += 4 + klen
    return out


def _parse_server_hello(body: bytes) -> dict | None:
    off = 2 + 32  # legacy_version + random
    if len(body) < off + 1:
        return None
    legacy_version = struct.unpack(">H", body[0:2])[0]
    sid_len = body[off]
    off += 1 + sid_len
    if len(body) < off + 3:
        return None
    cipher = struct.unpack(">H", body[off:off + 2])[0]
    off += 2 + 1  # cipher + legacy_compression_method
    selected_version: int | None = None
    group: int | None = None
    if len(body) >= off + 2:
        ext_total = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        selected_version, group = _parse_server_extensions(body[off:off + ext_total])
    return {"type": "server_hello", "legacy_version": legacy_version, "cipher": cipher,
            "selected_version": selected_version, "group": group}


def _parse_server_extensions(exts: bytes) -> tuple[int | None, int | None]:
    selected_version: int | None = None
    group: int | None = None
    i = 0
    while i + 4 <= len(exts):
        et = struct.unpack(">H", exts[i:i + 2])[0]
        el = struct.unpack(">H", exts[i + 2:i + 4])[0]
        ev = exts[i + 4:i + 4 + el]
        i += 4 + el
        if et == 0x002B and len(ev) >= 2:  # supported_versions (selected)
            selected_version = struct.unpack(">H", ev[0:2])[0]
        elif et == 0x0033 and len(ev) >= 2:  # key_share (selected group)
            group = struct.unpack(">H", ev[0:2])[0]
    return selected_version, group


# --- SSH KEXINIT extraction ---------------------------------------------

def parse_ssh_kexinit(payload: bytes) -> dict | None:
    """Extract the SSH-2.0 banner + KEXINIT name-lists from a TCP payload.

    Returns {"banner", "kex_algorithms" (list[str]),
    "server_host_key_algorithms" (list[str])} or None if no KEXINIT is present.
    """
    try:
        data = payload
        banner: str | None = None
        if data[:4] == b"SSH-":
            nl = data.find(b"\n")
            if nl == -1:
                return None  # banner only, KEXINIT not in this segment
            banner = data[:nl].rstrip(b"\r\n").decode("ascii", errors="replace")
            data = data[nl + 1:]
        if len(data) < 6:
            return None
        pkt_len = struct.unpack(">I", data[0:4])[0]
        pad_len = data[4]
        body_len = pkt_len - 1 - pad_len
        if body_len <= 0:
            return None
        ssh_payload = data[5:5 + body_len]
        if not ssh_payload or ssh_payload[0] != 20:  # SSH_MSG_KEXINIT
            return None
        i = 17  # msg type (1) + cookie (16)
        namelists: list[list[str]] = []
        for _ in range(2):  # kex_algorithms, server_host_key_algorithms
            if i + 4 > len(ssh_payload):
                return None
            ln = struct.unpack(">I", ssh_payload[i:i + 4])[0]
            i += 4
            value = ssh_payload[i:i + ln].decode("utf-8", errors="replace")
            i += ln
            namelists.append([t.strip() for t in value.split(",") if t.strip()])
        return {"banner": banner, "kex_algorithms": namelists[0],
                "server_host_key_algorithms": namelists[1]}
    except (struct.error, IndexError):
        return None
