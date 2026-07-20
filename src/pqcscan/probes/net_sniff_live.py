"""net.sniff.live — live passive TLS sniffer over a raw AF_PACKET socket.

Closes the "passive / SPAN sensing" gap the commercial peers cover (SandboxAQ,
Palo Alto PAN-OS, Cyberzero read live tapped traffic): instead of ingesting an
offline PCAP, this probe opens a raw ``AF_PACKET`` capture socket, listens for a
bounded window, and pulls the negotiated / advertised cryptography straight off
the wire — no libpcap, no scapy, pure stdlib. Linux-only; on any other OS (or
without CAP_NET_RAW) ``applies()`` returns False and no socket is ever opened.

Because a normal scan leaves ``ctx.sniff`` None, this probe is inert on every
ordinary run — it only wakes up for the dedicated ``pqcscan sniff`` command,
which sets a ``SniffConfig``.

What it reads off each TCP payload that starts a TLS handshake record (0x16):
- ClientHello  — the ``supported_groups`` extension. Advertised KEX groups are
  a *low*-confidence signal (the client offered them; they may not be chosen).
- ServerHello  — the negotiated ``cipher_suite`` and, in TLS 1.3, the selected
  ``key_share`` group. Negotiated = observed fact -> *medium* confidence.
- Certificate  — the leaf certificate's signature algorithm, parsed with the
  already-present ``cryptography`` lib -> *high* confidence (structured parse).

Parsing is delegated to the existing dependency-free helpers (``_pcap`` for the
link/IP/TCP + TLS-hello decode, ``net_tls_cert_chain`` for the DER certificate
extraction). Findings are de-duplicated per (src, dst, dport, alg, kind) and
capped so a busy link cannot emit thousands of identical rows. The blocking
capture loop runs in a thread-pool executor so it never stalls the event loop,
and nothing ever raises out of ``run()``.
"""
from __future__ import annotations

import asyncio
import socket
import sys
import time
from collections.abc import Callable, Iterable, Iterator

from cryptography import x509

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext, SniffConfig
from pqcscan.probes._pcap import decode_packet, parse_tls_handshake
from pqcscan.probes._severity import sev_for
from pqcscan.probes.fs_pcap_crypto import _CIPHER_SUITES, _TLS_GROUPS, _classify_suite
from pqcscan.probes.net_tls_cert_chain import extract_certificates

# Ethernet II is link-layer type 1 for _pcap.decode_packet; a raw AF_PACKET
# ETH_P_ALL socket hands us full Ethernet frames.
_LINKTYPE_ETHERNET = 1
_ETH_P_ALL = 0x0003  # capture every ethertype (Linux <linux/if_ether.h>)

# Cap total findings so a busy tap cannot emit thousands of rows in one window.
_MAX_FINDINGS = 500

# A single decoded crypto observation: (record_kind, algorithm, classification,
# confidence, advertised).
_Observation = tuple[str, str, Classification, str, bool]

FrameSource = Callable[[SniffConfig], Iterable[bytes]]


class NetSniffLive(Probe):
    """Live passive TLS capture off a raw AF_PACKET socket (Linux only)."""

    id = "net.sniff.live"
    family = ProbeFamily.NETWORK
    requires = frozenset({Capability.NET_RAW})
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, *, frame_source: FrameSource | None = None) -> None:
        # Injectable for tests: frame_source(cfg) -> iterable of raw link-layer
        # frames. Default None -> real AF_PACKET capture. Tests pass a canned
        # iterable so no real socket is ever opened in CI.
        self._frame_source = frame_source

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            ctx.sniff is not None
            and sys.platform.startswith("linux")
            and Capability.NET_RAW in ctx.available_capabilities
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        cfg = ctx.sniff
        if cfg is None:  # pragma: no cover — applies() already gates this
            return
        try:
            frames = await self._collect(cfg)
        except Exception:  # pragma: no cover — belt-and-suspenders, never raise
            frames = None
        if frames is None:
            emit(_info(self.id, f"live capture unavailable on {_iface_label(cfg)}"))
            return
        try:
            self._process(frames, cfg, emit)
        except Exception:  # pragma: no cover — parsing is defensive; last resort
            return

    async def _collect(self, cfg: SniffConfig) -> list[bytes] | None:
        """Gather raw frames — from the injected source, or a real socket run
        off the event loop in a worker thread so recv() never blocks it."""
        if self._frame_source is not None:
            return list(self._frame_source(cfg))
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._capture, cfg)

    def _capture(self, cfg: SniffConfig) -> list[bytes] | None:
        """Blocking raw-socket capture loop. Returns the frames, or None when
        the socket could not be opened (no privilege / not Linux)."""
        # AF_PACKET is Linux-only; guard the constant so import stays clean and
        # a mis-gated call degrades to "unavailable" instead of crashing.
        af_packet = getattr(socket, "AF_PACKET", None)
        if af_packet is None:
            return None
        try:
            sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        except (OSError, PermissionError):
            return None
        frames: list[bytes] = []
        try:
            if cfg.interface:
                sock.bind((cfg.interface, 0))
            sock.settimeout(0.5)
            deadline = time.monotonic() + cfg.seconds
            while time.monotonic() < deadline and len(frames) < cfg.max_packets:
                try:
                    frame = sock.recv(65535)
                except TimeoutError:  # settimeout expiry — re-check the deadline
                    continue
                except OSError:
                    break
                if frame:
                    frames.append(frame)
        finally:
            sock.close()
        return frames

    def _process(self, frames: Iterable[bytes], cfg: SniffConfig, emit: Emitter) -> None:
        seen: set[tuple[str, str, int, str, str]] = set()
        emitted = 0
        saw_crypto = False
        capped = False
        for frame in frames:
            seg = decode_packet(frame, _LINKTYPE_ETHERNET)
            if seg is None or seg.proto != "tcp" or not seg.payload:
                continue
            for kind, alg, cls, confidence, advertised in _analyze(seg.payload):
                key = (seg.src_ip, seg.dst_ip, seg.dst_port, alg, kind)
                if key in seen:
                    continue
                seen.add(key)
                saw_crypto = True
                if emitted >= _MAX_FINDINGS:
                    capped = True
                    break
                emit(_finding(self.id, seg, kind, alg, cls, confidence, advertised))
                emitted += 1
            if capped:
                break

        if capped:
            emit(_info(
                self.id,
                f"finding cap ({_MAX_FINDINGS}) reached on {_iface_label(cfg)} — "
                f"output truncated",
            ))
        if not saw_crypto:
            emit(_info(
                self.id,
                f"no TLS handshakes observed in {cfg.seconds:g}s on {_iface_label(cfg)}",
            ))


def _analyze(payload: bytes) -> Iterator[_Observation]:
    """Yield crypto observations from a single TCP payload's TLS handshake."""
    tls = parse_tls_handshake(payload)
    if tls is not None:
        if tls["type"] == "client_hello":
            yield from _client_hello_obs(tls)
        elif tls["type"] == "server_hello":
            yield from _server_hello_obs(tls)
        return
    # Not a hello — maybe a (cleartext, TLS<=1.2) Certificate message.
    yield from _certificate_obs(payload)


def _client_hello_obs(tls: dict) -> Iterator[_Observation]:
    # supported_groups are ADVERTISED — a low-confidence signal.
    for code in tls["groups"]:
        info = _TLS_GROUPS.get(code)
        if info is None:  # unknown / GREASE — don't emit noise
            continue
        name, is_pqc = info
        cls = Classification.PQC_READY if is_pqc else Classification.TINGGI
        yield "client_hello", name, cls, "low", True


def _server_hello_obs(tls: dict) -> Iterator[_Observation]:
    # Negotiated cipher suite — an observed fact -> medium confidence.
    name = _CIPHER_SUITES.get(tls["cipher"])
    if name is not None:
        cls = _classify_suite(name)
        if cls is not Classification.INFO:
            yield "server_hello", name, cls, "medium", False
    # TLS 1.3 selected key_share group.
    group = tls["group"]
    if group is not None:
        info = _TLS_GROUPS.get(group)
        if info is not None:
            gname, is_pqc = info
            gcls = Classification.PQC_READY if is_pqc else Classification.TINGGI
            yield "server_hello", gname, gcls, "medium", False


def _certificate_obs(payload: bytes) -> Iterator[_Observation]:
    certs = extract_certificates(payload)
    if not certs:
        return
    try:
        leaf = x509.load_der_x509_certificate(certs[0])
    except (ValueError, TypeError):
        return
    oid = leaf.signature_algorithm_oid.dotted_string
    alg = normalise(oid)
    # A structured DER parse is the strongest signal -> high confidence.
    yield "certificate", alg, classify(alg), "high", False


def _finding(
    probe_id: str,
    seg: object,
    kind: str,
    alg: str,
    cls: Classification,
    confidence: str,
    advertised: bool,
) -> Finding:
    src = getattr(seg, "src", "?")
    dst = getattr(seg, "dst", "?")
    dst_port = getattr(seg, "dst_port", 0)
    evidence: dict[str, object] = {
        "src": src,
        "dst": dst,
        "dst_port": dst_port,
        "record": kind,
        "algorithm": alg,
        "confidence": confidence,
    }
    if advertised:
        evidence["advertised"] = True
    verb = "advertised" if advertised else "negotiated" if kind == "server_hello" else "served"
    return Finding(
        probe_id=probe_id,
        algorithm=alg,
        classification=cls,
        severity=sev_for(cls),
        title=f"live: {kind} {verb} {alg} ({src} -> {dst})",
        evidence=evidence,
        confidence=confidence,
    )


def _info(probe_id: str, message: str) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title=message,
        evidence={"note": message},
        confidence="high",
    )


def _iface_label(cfg: SniffConfig) -> str:
    return cfg.interface or "all interfaces"
