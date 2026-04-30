from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class NetTlsPop3s(Probe):
    id = "net.tls.pop3s"
    family = ProbeFamily.NETWORK
    framework_tags = (
        "nist-ir-8547:tls", "cnsa2:tls", "bukukerja:tls", "mykripto:tls",
    )

    def __init__(
        self, host: str = "127.0.0.1", port: int = 995, verify: bool = False
    ):
        self.host = host
        self.port = port
        self.verify = verify

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        await run_tls_probe(
            host=self.host, port=self.port, verify=self.verify,
            probe_id=self.id, emit=emit,
        )
