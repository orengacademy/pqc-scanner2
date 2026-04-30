"""net.db.mysql_tls — MySQL SSL upgrade probe (STUB in v0.1.0).

MySQL/MariaDB use a custom client-server handshake. Server sends an
'Initial Handshake Packet' with capability flags; client responds with
'SSL Request Packet' (CLIENT_SSL bit set) before upgrading. v0.1.0
emits a deferral notice; the full implementation lives in a follow-up
batch that vendors a small MySQL packet encoder.
"""
from __future__ import annotations

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class NetDbMysqlTls(Probe):
    id = "net.db.mysql_tls"
    family = ProbeFamily.NETWORK
    framework_tags = ("bukukerja:db", "mykripto:db", "nist-ir-8547:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 3306, verify: bool = False):
        self.host = host
        self.port = port
        self.verify = verify

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        emit(Finding(
            probe_id=self.id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=(
                f"MySQL TLS probe at {self.host}:{self.port} not yet implemented "
                "(needs MySQL handshake encoder)"
            ),
            evidence={
                "endpoint": f"{self.host}:{self.port}",
                "deferred_to": "Plan B follow-up batch (MySQL CLIENT_SSL handshake)",
            },
        ))
