"""fs.pcap.crypto — passive PCAP crypto extractor (the deferred "passive PCAP" item).

Walks ctx.scan_paths for *.pcap / *.pcapng capture files and, fully offline,
pulls the cryptography that was negotiated on the wire out of the handshakes:

- TLS   — ClientHello (offered cipher suites, supported_versions, supported_groups
          / key_share) and ServerHello (selected cipher suite, version, key_share
          group). The negotiated version, cipher suite, and KEX group are each
          classified for post-quantum exposure.
- SSH    — the SSH-2.0 banner + SSH_MSG_KEXINIT name-lists (kex_algorithms,
          server_host_key_algorithms).
- QUIC   — the client Initial packet (UDP) is decrypted (RFC 9001 keys derived
          from the on-the-wire DCID) to reach the TLS ClientHello inside its
          CRYPTO frame, then its offered (PQC/hybrid) groups are inventoried —
          a surface no other FOSS scanner reads. See `_quic`.

Parsing is delegated to `_pcap` (a hand-rolled, dependency-free pcap/pcapng +
TLS/SSH reader — no scapy/dpkt/pyshark). Everything is guarded: a truncated,
garbage, or non-pcap file yields no findings and never raises.

One finding is emitted per distinct (protocol, endpoint, algorithm). Findings
are de-duplicated and capped per file so a large capture can't emit thousands of
identical rows; when the cap is hit a note is added.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._pcap import (
    Segment,
    decode_packet,
    iter_packets,
    parse_ssh_kexinit,
    parse_tls_handshake,
)
from pqcscan.probes._quic import extract_client_hello
from pqcscan.probes._severity import classify_cipher_token, sev_for

# Cap findings per file so a huge capture with the same repeated handshake does
# not emit thousands of identical rows.
_MAX_FINDINGS_PER_FILE = 512

_PCAP_GLOBS = ("*.pcap", "*.pcapng")

# TLS version code -> human-readable name. <= TLS 1.1 is a broken/deprecated
# transport (SANGAT_TINGGI).
_TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}
_WEAK_TLS_VERSIONS = frozenset({0x0300, 0x0301, 0x0302})

# TLS supported_groups / key_share code -> (name, is_pqc). Classical ECDHE/FFDHE
# groups are quantum-vulnerable KEX (TINGGI); hybrids are PQC_READY.
_TLS_GROUPS: dict[int, tuple[str, bool]] = {
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

# TLS cipher-suite code -> RFC name. Unknown codes (incl. GREASE) map to None and
# are skipped, so we never emit noise for suites we can't name/classify.
_CIPHER_SUITES: dict[int, str] = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
}


def _classify_suite(name: str) -> Classification:
    """Classify a TLS cipher suite by its RFC name for PQC exposure.

    Weak symmetric primitives (RC4/3DES/DES/MD5/NULL/EXPORT/anon) and legacy
    CBC-mode-with-SHA1 suites are SANGAT_TINGGI; static-RSA key transport and
    classical (EC)DHE key exchange are quantum-broken -> TINGGI. Bare TLS 1.3
    AEAD suites carry no KEX in the name (that lives in key_share) -> INFO.
    """
    up = name.upper()
    base = classify_cipher_token(name)
    if base is Classification.SANGAT_TINGGI:
        return base
    if up.endswith("_CBC_SHA"):  # CBC cipher + SHA-1 MAC, no AEAD
        return Classification.SANGAT_TINGGI
    if "_RSA_WITH" in up and "DHE" not in up:  # static-RSA key transport
        return Classification.TINGGI
    if "ECDHE" in up or "ECDH_" in up or "DHE_" in up:  # classical KEX
        return Classification.TINGGI
    return base


def _classify_ssh_kex(token: str) -> tuple[str, Classification]:
    """Classify an SSH kex algorithm token; returns (algorithm, classification)."""
    low = token.lower()
    if any(frag in low for frag in ("sntrup", "mlkem", "ml-kem", "kyber")):
        return token, Classification.PQC_READY
    if low.startswith("curve25519"):  # ECDH over Curve25519 — Shor-broken
        return token, Classification.TINGGI
    if low.startswith(("ecdh-sha2", "ecdh")):
        return token, Classification.TINGGI
    if low.startswith("diffie-hellman-group1-") or low.endswith("group1-sha1"):
        return token, Classification.SANGAT_TINGGI  # 1024-bit MODP + SHA-1
    if low.startswith("diffie-hellman"):  # group14/16/18 — classical FFDHE
        return token, Classification.TINGGI
    return token, Classification.INFO


# SSH host-key / KEX name -> canonical alg for classify(). Mirrors _ssh_parser.
_SSH_HOSTKEY_ALIASES: dict[str, str] = {
    "ssh-rsa": "RSA-2048",
    "rsa-sha2-256": "RSA-2048",
    "rsa-sha2-512": "RSA-2048",
    "ssh-dss": "DSA",
    "ecdsa-sha2-nistp256": "ECDSA-SHA256",
    "ecdsa-sha2-nistp384": "ECDSA-SHA384",
    "ecdsa-sha2-nistp521": "ECDSA-SHA512",
    "ssh-ed25519": "Ed25519",
    "ssh-ed448": "Ed448",
}


def _classify_ssh_hostkey(token: str) -> tuple[str, Classification]:
    low = token.lower()
    if any(frag in low for frag in ("mldsa", "ml-dsa", "dilithium", "sphincs", "falcon")):
        return token, Classification.PQC_READY
    canonical = _SSH_HOSTKEY_ALIASES.get(low)
    if canonical is None:
        canonical = normalise(token)
    return token, classify(canonical)


class FsPcapCrypto(Probe):
    """Passively extract negotiated TLS/SSH crypto from offline packet captures."""

    id = "fs.pcap.crypto"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        roots = self.roots if self.roots is not None else ctx.scan_paths
        for path in _iter_pcap_files(roots):
            try:
                self._scan_file(path, emit)
            except Exception:  # pragma: no cover — belt-and-suspenders, never raise
                continue

    def _scan_file(self, path: Path, emit: Emitter) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        seen: set[tuple[str, str, str]] = set()
        emitted = 0
        capped = False
        try:
            for frame, linktype in iter_packets(data):
                seg = decode_packet(frame, linktype)
                if seg is None or seg.proto not in ("tcp", "udp") or not seg.payload:
                    continue
                for proto, alg, cls in self._analyze(seg.payload, seg.proto):
                    endpoint = f"{seg.src}->{seg.dst}"
                    key = (proto, endpoint, alg)
                    if key in seen:
                        continue
                    seen.add(key)
                    if emitted >= _MAX_FINDINGS_PER_FILE:
                        capped = True
                        break
                    emit(_finding(self.id, path, seg, proto, alg, cls))
                    emitted += 1
                if capped:
                    break
        except Exception:  # pragma: no cover — parser is defensive, this is a backstop
            return
        if capped:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"{path.name}: finding cap ({_MAX_FINDINGS_PER_FILE}) reached — "
                      f"output truncated",
                evidence={"file": str(path), "cap": _MAX_FINDINGS_PER_FILE},
            ))

    def _analyze(
        self, payload: bytes, proto: str = "tcp",
    ) -> Iterator[tuple[str, str, Classification]]:
        if proto == "udp":
            # QUIC: decrypt the Initial packet to reach the TLS ClientHello and
            # inventory its offered (PQC/hybrid) groups — a surface no other FOSS
            # scanner reads. Tagged "quic" so it's distinguishable from TLS/TCP.
            ch = extract_client_hello(payload)
            if ch is not None:
                tls = parse_tls_handshake(_wrap_tls_record(ch))
                if tls is not None:
                    for _p, alg, cls in _analyze_tls(tls):
                        yield "quic", alg, cls
            return
        tls = parse_tls_handshake(payload)
        if tls is not None:
            yield from _analyze_tls(tls)
            return
        ssh = parse_ssh_kexinit(payload)
        if ssh is not None:
            yield from _analyze_ssh(ssh)


def _wrap_tls_record(handshake: bytes) -> bytes:
    """Wrap a bare TLS handshake message (from a QUIC CRYPTO frame) in a TLS 1.2
    record so the record-oriented ``parse_tls_handshake`` can read it."""
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def _analyze_tls(tls: dict) -> Iterator[tuple[str, str, Classification]]:
    if tls["type"] == "client_hello":
        for code in tls["cipher_suites"]:
            name = _CIPHER_SUITES.get(code)
            if name is None:
                continue
            cls = _classify_suite(name)
            if cls is not Classification.INFO:
                yield "tls", name, cls
        for code in tls["groups"]:
            info = _TLS_GROUPS.get(code)
            if info is not None and info[1]:  # only surface PQC groups from an offer
                yield "tls", info[0], Classification.PQC_READY
    elif tls["type"] == "server_hello":
        effective = tls["selected_version"] or tls["legacy_version"]
        if effective in _WEAK_TLS_VERSIONS:
            yield "tls", _TLS_VERSIONS[effective], Classification.SANGAT_TINGGI
        name = _CIPHER_SUITES.get(tls["cipher"])
        if name is not None:
            cls = _classify_suite(name)
            if cls is not Classification.INFO:
                yield "tls", name, cls
        if tls["group"] is not None:
            gname, is_pqc = _TLS_GROUPS.get(tls["group"], (f"group-0x{tls['group']:04x}", False))
            yield "tls", gname, (Classification.PQC_READY if is_pqc else Classification.TINGGI)


def _analyze_ssh(ssh: dict) -> Iterator[tuple[str, str, Classification]]:
    for token in ssh["kex_algorithms"]:
        alg, cls = _classify_ssh_kex(token)
        if cls is not Classification.INFO:
            yield "ssh", alg, cls
    for token in ssh["server_host_key_algorithms"]:
        alg, cls = _classify_ssh_hostkey(token)
        if cls is not Classification.INFO:
            yield "ssh", alg, cls


def _finding(
    probe_id: str, path: Path, seg: Segment, proto: str, alg: str, cls: Classification,
) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm=alg,
        classification=cls,
        severity=sev_for(cls),
        title=f"{path.name}: {proto.upper()} {alg} negotiated ({seg.src} -> {seg.dst})",
        evidence={
            "file": str(path),
            "src": seg.src,
            "dst": seg.dst,
            "proto": proto,
        },
    )


def _iter_pcap_files(roots: list[Path]) -> Iterator[Path]:
    for root in roots:
        try:
            if root.is_file():
                if root.suffix.lower() in (".pcap", ".pcapng"):
                    yield root
                continue
            if not root.is_dir():
                continue
            for pat in _PCAP_GLOBS:
                yield from root.rglob(pat)
        except OSError:
            continue
