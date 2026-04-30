from __future__ import annotations

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class NetStarttlsLdap(Probe):
    """LDAP STARTTLS uses a binary ExtendedRequest with OID 1.3.6.1.4.1.1466.20037.

    v0.1.0 emits a deferral notice; full implementation arrives in a later batch
    that vendors a small ASN.1 DER encoder. Use net.tls.ldaps for now to scan
    LDAPS on port 636 directly.
    """
    id = "net.starttls.ldap"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, host: str = "127.0.0.1", port: int = 389, verify: bool = False):
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
                f"LDAP STARTTLS at {self.host}:{self.port} not yet implemented; "
                "use net.tls.ldaps (port 636) for direct TLS coverage"
            ),
            evidence={
                "endpoint": f"{self.host}:{self.port}",
                "deferred_to": "Plan B batch (binary LDAP DER encoder)",
            },
        ))
