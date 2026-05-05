from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class HostOpenSSLEngines(Probe):
    """Run `openssl engine -t -c` and flag legacy engines/providers."""
    id = "host.openssl.engines"
    family = ProbeFamily.HOST
    framework_tags = ("bukukerja:host", "mykripto:host")

    def __init__(self, openssl: str | None = None):
        self.openssl = openssl

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.openssl or "openssl") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.openssl or "openssl"
        proc = await asyncio.create_subprocess_exec(
            bin_path, "engine", "-t", "-c",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        if "legacy" in text.lower():
            emit(Finding(
                probe_id=self.id,
                algorithm="MD5/RC4/etc-via-legacy-engine",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.HIGH,
                title="OpenSSL legacy engine listed in `openssl engine -t -c`",
                evidence={"output": text[:400]},
                remediation={
                    "snippet": "# Remove `engines` section from openssl.cnf or do not load `legacy`",
                },
            ))
