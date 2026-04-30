"""storage.fscrypt — detect fscrypt usage via /proc/cmdline + fscrypt binary."""
from __future__ import annotations

import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class StorageFscrypt(Probe):
    id = "storage.fscrypt"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage", "mykripto:storage")

    def __init__(self, cmdline_path: Path | None = None):
        self.cmdline_path = cmdline_path or Path("/proc/cmdline")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.cmdline_path.exists() or shutil.which("fscrypt") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        evidence: dict = {}
        cmdline = ""
        if self.cmdline_path.exists():
            try:
                cmdline = self.cmdline_path.read_text(errors="replace")
            except OSError:
                cmdline = ""
        if "fscrypt" in cmdline.lower():
            evidence["cmdline_match"] = True
        if shutil.which("fscrypt"):
            evidence["fscrypt_binary"] = shutil.which("fscrypt")
        if not evidence:
            return
        # fscrypt defaults to AES-256-XTS for content, AES-256-CTS for filenames —
        # report as Rendah (low risk per spec's AES-256 row).
        emit(Finding(
            probe_id=self.id,
            algorithm="AES-256-XTS",
            classification=Classification.RENDAH,
            severity=Severity.LOW,
            title="fscrypt detected (AES-256-XTS for file content)",
            evidence=evidence,
        ))
