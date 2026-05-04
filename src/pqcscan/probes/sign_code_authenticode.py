"""sign.code.authenticode — Windows Authenticode (skip on non-Windows)."""
from __future__ import annotations

import asyncio
import shutil
import sys

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class SignCodeAuthenticode(Probe):
    id = "sign.code.authenticode"
    family = ProbeFamily.SIGN
    framework_tags = ("bukukerja:sign", "mykripto:sign")

    async def applies(self, ctx: ScanContext) -> bool:
        return sys.platform == "win32" and shutil.which("powershell") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        if sys.platform != "win32":
            return
        # Query system32 binaries' Authenticode signatures via PowerShell.
        ps = ("Get-ChildItem 'C:\\Windows\\System32\\*.exe' | "
              "Get-AuthenticodeSignature | "
              "Select-Object -First 10 SignerCertificate.SignatureAlgorithm.FriendlyName,Status | "
              "ConvertTo-Json")
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-Command", ps,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")
        # Look for sha1 in signature algorithm output.
        if "sha1" in text.lower():
            emit(Finding(
                probe_id=self.id,
                algorithm="SHA-1",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.HIGH,
                title="Authenticode signatures using SHA-1 detected on system binaries",
                evidence={"snippet": text[:400]},
            ))
