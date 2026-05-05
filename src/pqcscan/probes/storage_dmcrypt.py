"""storage.dmcrypt — `dmsetup table --target crypt` for active dm-crypt mappings."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.alg import classify
from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class StorageDmcrypt(Probe):
    id = "storage.dmcrypt"
    family = ProbeFamily.STORAGE
    requires = frozenset({Capability.ROOT})
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage", "mykripto:storage")

    def __init__(self, dmsetup_bin: str | None = None):
        self.dmsetup_bin = dmsetup_bin

    async def applies(self, ctx: ScanContext) -> bool:
        if Capability.ROOT not in ctx.available_capabilities:
            return False
        return shutil.which(self.dmsetup_bin or "dmsetup") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            self.dmsetup_bin or "dmsetup", "table", "--target", "crypt",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except TimeoutError:
            proc.kill()
            return
        # Each line: "<name>: <start> <len> crypt <cipher> <key> <iv> <device> <off>"
        for raw in stdout.decode("utf-8", errors="replace").splitlines():
            if "crypt" not in raw:
                continue
            parts = raw.split()
            try:
                # cipher token sits two slots after "crypt" keyword
                idx = parts.index("crypt")
                cipher_token = parts[idx + 1]
            except (ValueError, IndexError):
                continue
            # cipher_token examples: "aes-xts-plain64", "aes-cbc-essiv:sha256"
            cipher_canonical = cipher_token.split(":", 1)[0].upper()
            cls = classify(cipher_canonical)
            emit(Finding(
                probe_id=self.id,
                algorithm=cipher_token,
                classification=cls,
                severity=_sev(cls),
                title=f"dm-crypt mapping {parts[0].rstrip(':')} cipher = {cipher_token}",
                evidence={"line": raw},
            ))


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]
