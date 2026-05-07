"""ot.coap.dtls — DTLS handshake against CoAPS endpoint on UDP/5684."""
from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, OTTarget, Probe, ScanContext
from pqcscan.probes._dtls_probe import run_dtls_probe


class OTCoapDtls(Probe):
    id = "ot.coap.dtls"
    family = ProbeFamily.OT
    framework_tags = ("nacsa-9:ot", "bukukerja:ot")

    async def applies(self, ctx: ScanContext) -> bool:
        return any(t.proto_hint in (None, "coap_dtls") for t in ctx.ot_targets) or not ctx.ot_targets

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        targets = [t for t in ctx.ot_targets if t.proto_hint in (None, "coap_dtls")]
        if not targets:
            targets = [OTTarget(host="127.0.0.1", port=5684, proto_hint="coap_dtls")]
        for target in targets:
            await run_dtls_probe(
                host=target.host, port=target.port, version="1.2",
                probe_id=self.id, emit=emit,
            )
