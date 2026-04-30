"""net.db.mongo_tls — direct TLS probe against MongoDB.

MongoDB 6+ supports implicit TLS on its port (no plaintext-to-TLS upgrade
handshake required). We reuse the generic _tls_probe helper. If the server
listens but doesn't speak TLS, the helper emits a TLS-handshake-failure
INFO finding which itself is useful signal (server is plaintext-only).
"""
from __future__ import annotations

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._tls_probe import run_tls_probe


class NetDbMongoTls(Probe):
    id = "net.db.mongo_tls"
    family = ProbeFamily.NETWORK
    framework_tags = ("bukukerja:db", "mykripto:db", "nist-ir-8547:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 27017, verify: bool = False):
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
