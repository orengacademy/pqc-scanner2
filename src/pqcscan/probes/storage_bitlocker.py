"""storage.bitlocker — Windows-only BitLocker status via manage-bde."""
from __future__ import annotations

import asyncio
import shutil
import sys

from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class StorageBitlocker(Probe):
    id = "storage.bitlocker"
    family = ProbeFamily.STORAGE
    requires = frozenset({Capability.ROOT})  # manage-bde needs admin on Windows
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage", "mykripto:storage")

    async def applies(self, ctx: ScanContext) -> bool:
        return sys.platform == "win32" and shutil.which("manage-bde") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        if sys.platform != "win32":
            return
        proc = await asyncio.create_subprocess_exec(
            "manage-bde", "-status",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except asyncio.TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")

        # BitLocker pre-Win10 used AES-128 by default; Win10+ uses XTS-AES-128/256.
        # We flag any AES-128-based encryption as Tinggi (sub-256 boundary).
        if "AES 128" in text or "XTS-AES 128" in text:
            emit(Finding(
                probe_id=self.id,
                algorithm="AES-128",
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title="BitLocker uses AES-128 (consider XTS-AES-256)",
                evidence={"output_excerpt": text[:400]},
                remediation={"snippet": "manage-bde -on <vol> -encryption-method XTSAES256"},
            ))
