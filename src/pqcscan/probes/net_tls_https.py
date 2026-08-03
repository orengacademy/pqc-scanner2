from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class NetTlsHttps(Probe):
    id = "net.tls.https"
    family = ProbeFamily.NETWORK
    framework_tags = (
        "nist-ir-8547:tls", "cnsa2:tls", "bukukerja:tls", "mykripto:tls",
    )

    def __init__(
        self, host: str | None = None, port: int = 443, verify: bool = False
    ):
        self.host = host
        self.port = port
        self.verify = verify

    def _resolve_target(self, ctx: ScanContext) -> tuple[str, int]:
        """Explicit constructor host wins, then `--target`, then localhost."""
        if self.host:
            return self.host, self.port
        if ctx.server_target:
            host, _, port = ctx.server_target.partition(":")
            if host:
                try:
                    return host, int(port) if port else 443
                except ValueError:
                    pass
        return "127.0.0.1", self.port

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        host, port = self._resolve_target(ctx)
        await run_tls_probe(
            host=host, port=port, verify=self.verify,
            probe_id=self.id, emit=emit,
        )
