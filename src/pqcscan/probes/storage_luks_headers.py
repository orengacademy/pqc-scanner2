"""storage.luks.headers — root-only LUKS header dump via cryptsetup."""
from __future__ import annotations

import asyncio
import re
import shutil

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Capability, Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_LUKS_CIPHER_RE = re.compile(r"^\s*Cipher\s*name:\s*(\S+)", re.MULTILINE | re.IGNORECASE)
_LUKS_KEYBITS_RE = re.compile(r"^\s*MK\s*bits:\s*(\d+)", re.MULTILINE | re.IGNORECASE)


class StorageLuksHeaders(Probe):
    id = "storage.luks.headers"
    family = ProbeFamily.STORAGE
    requires = frozenset({Capability.ROOT})
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage", "mykripto:storage")

    def __init__(self, lsblk_bin: str | None = None, cryptsetup_bin: str | None = None):
        self.lsblk_bin = lsblk_bin
        self.cryptsetup_bin = cryptsetup_bin

    async def applies(self, ctx: ScanContext) -> bool:
        if Capability.ROOT not in ctx.available_capabilities:
            return False
        return (
            shutil.which(self.cryptsetup_bin or "cryptsetup") is not None
            and shutil.which(self.lsblk_bin or "lsblk") is not None
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        # Find LUKS-formatted block devices via lsblk.
        proc = await asyncio.create_subprocess_exec(
            self.lsblk_bin or "lsblk", "-no", "NAME,FSTYPE",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except TimeoutError:
            proc.kill()
            return

        for line in stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name, fstype = parts[0], parts[1]
            if fstype != "crypto_LUKS":
                continue
            await self._dump_one(f"/dev/{name.lstrip('|`-')}", emit)

    async def _dump_one(self, device: str, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            self.cryptsetup_bin or "cryptsetup", "luksDump", device,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except TimeoutError:
            proc.kill()
            return
        text = stdout.decode("utf-8", errors="replace")

        cipher_m = _LUKS_CIPHER_RE.search(text)
        bits_m = _LUKS_KEYBITS_RE.search(text)
        if not cipher_m:
            return
        cipher_name = cipher_m.group(1).lower()  # e.g. aes
        bits = bits_m.group(1) if bits_m else ""

        canonical = f"{cipher_name.upper()}-{bits}" if bits else cipher_name.upper()
        cls = classify(canonical)
        emit(Finding(
            probe_id=self.id,
            algorithm=normalise(canonical),
            classification=cls,
            severity=_sev(cls),
            title=f"LUKS device {device} cipher = {canonical}",
            evidence={"device": device, "cipher_name": cipher_name, "key_bits": bits},
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
