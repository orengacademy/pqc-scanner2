from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._starttls_probe import SMTP, run_starttls_probe


class NetStarttlsSmtp(Probe):
    id = "net.starttls.smtp"
    family = ProbeFamily.NETWORK
    framework_tags = (
        "nist-ir-8547:tls", "cnsa2:tls", "bukukerja:tls", "mykripto:tls",
    )

    def __init__(
        self, host: str = "127.0.0.1", port: int = 25, verify: bool = False
    ):
        self.host = host
        self.port = port
        self.verify = verify

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        await run_starttls_probe(
            host=self.host, port=self.port, protocol=SMTP,
            probe_id=self.id, emit=emit, verify=self.verify,
        )
