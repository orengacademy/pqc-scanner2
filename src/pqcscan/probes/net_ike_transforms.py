"""net.ike.transforms — enumerate an IKEv2 responder's SA transforms.

Goes deeper than ``net.ike.v1v2`` (bare UDP-500 detection): it sends a real
IKE_SA_INIT with a rich SAi1 proposal (multiple ENCR/PRF/INTEG/DH transforms
incl. classical groups + a PQC ML-KEM group per RFC 9370), then parses the
responder's SAr1 — its single *chosen* transform set — and classifies each
transform for post-quantum readiness. Classical MODP/ECP DH groups are
Shor-vulnerable (harvest-now-decrypt-later); RFC 9370 ML-KEM groups are
PQC-ready. DES/3DES are flagged as weak.

IKE responders are frequently filtered or refuse an incomplete initiator, so a
silent target is normal: in that case the probe still emits an INFO recording
the offered proposal so the operator sees the client-side posture.
"""
from __future__ import annotations

import asyncio
import socket

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._ike_packet import (
    build_ike_sa_init,
    extract_sa_payload,
    offered_transforms,
    parse_sa_payload,
)
from pqcscan.probes._severity import sev_for

_DEFAULT_IKE_PORT = 500


class NetIkeTransforms(Probe):
    """Enumerate a responder's chosen IKE_SA_INIT SA transforms."""

    id = "net.ike.transforms"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:ipsec", "mykripto:vpn")

    def __init__(self, target: str | None = None, timeout: float = 3.0):
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
            return host, _DEFAULT_IKE_PORT
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
        try:
            reply = await self._exchange(host, port)
        except Exception:  # probe must never raise; treat any fault as no reply
            reply = None

        transforms: list[dict] = []
        if reply is not None:
            try:
                sa = extract_sa_payload(reply)
                if sa is not None:
                    transforms = parse_sa_payload(sa)
            except Exception:  # a malformed reply is a clean "no transforms"
                transforms = []

        if not transforms:
            self._emit_no_response(host, port, reply, emit)
            return

        for tf in transforms:
            cls: Classification = tf["classification"]
            emit(Finding(
                probe_id=self.id,
                algorithm=tf["name"],
                classification=cls,
                severity=sev_for(cls),
                title=(f"IKEv2 {host}:{port} negotiated {_TYPE_LABEL.get(tf['type'], 'transform')} "
                       f"{tf['name']}"),
                evidence={
                    "host": host,
                    "port": port,
                    "transform_type": tf["type"],
                    "transform_id": tf["id"],
                    "key_length": tf["key_len"],
                    "name": tf["name"],
                },
            ))

    def _emit_no_response(self, host: str, port: int, reply: bytes | None, emit: Emitter) -> None:
        offered = offered_transforms()
        note = ("No parseable SAr1 returned (IKE responders are commonly filtered or reject "
                "an incomplete initiator). Reporting the offered proposal so the client-side "
                "posture is still visible.")
        emit(Finding(
            probe_id=self.id,
            algorithm="IKEv2/IKE_SA_INIT",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"IKEv2 {host}:{port} — no SA transforms parsed (offered {len(offered)} transforms)",
            evidence={
                "host": host,
                "port": port,
                "response_bytes": len(reply) if reply is not None else 0,
                "offered": [
                    {"name": t["name"], "classification": str(t["classification"])}
                    for t in offered
                ],
                "note": note,
            },
        ))

    async def _exchange(self, host: str, port: int) -> bytes | None:
        """Send one IKE_SA_INIT over UDP and read the responder's reply."""
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=self.timeout)
            await loop.sock_sendall(sock, build_ike_sa_init())
            try:
                return await asyncio.wait_for(loop.sock_recv(sock, 8192), timeout=self.timeout)
            except (TimeoutError, OSError):
                return None
        finally:
            sock.close()


_TYPE_LABEL: dict[int, str] = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH"}
