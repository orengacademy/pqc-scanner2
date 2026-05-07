"""host.openssl.oqs_provider — detect oqs-provider in local OpenSSL.

Plan I.7.a — checks if `oqsprovider` is loaded in the host's OpenSSL via
`openssl list -providers`. Independent of the `pqcscan[active]` Python
extras: this probe runs with default install since it only shells out
to the system openssl binary.
"""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class HostOpenSSLOqsProvider(Probe):
    id = "host.openssl.oqs_provider"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:tls", "cnsa2:tls")

    def __init__(self, openssl_bin: str | None = None) -> None:
        self.openssl_bin = openssl_bin

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.openssl_bin or "openssl") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        bin_path = self.openssl_bin or "openssl"
        try:
            proc = await asyncio.create_subprocess_exec(
                bin_path, "list", "-providers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (TimeoutError, OSError) as e:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"openssl list -providers failed: {e}",
                evidence={"error": repr(e)},
            ))
            return

        text = stdout_b.decode("utf-8", errors="replace")
        text_lower = text.lower()
        oqs_loaded = "oqsprovider" in text_lower or "oqs-provider" in text_lower

        if oqs_loaded:
            emit(Finding(
                probe_id=self.id,
                algorithm="oqs-provider",
                classification=Classification.PQC_READY,
                severity=Severity.INFO,
                title="oqs-provider loaded in local OpenSSL",
                evidence={"providers_raw": text},
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.LOW,
                title="oqs-provider not loaded in local OpenSSL",
                evidence={
                    "providers_raw": text,
                    "remediation": "Install oqs-provider and load via openssl.cnf or OPENSSL_MODULES.",
                },
            ))
