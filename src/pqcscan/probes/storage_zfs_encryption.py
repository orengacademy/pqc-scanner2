"""storage.zfs.encryption — `zfs get encryption,keyformat` for native ZFS encryption."""
from __future__ import annotations

import asyncio
import shutil

from pqcscan.core.alg import classify
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class StorageZfsEncryption(Probe):
    id = "storage.zfs.encryption"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage", "mykripto:storage")

    def __init__(self, zfs_bin: str | None = None):
        self.zfs_bin = zfs_bin

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which(self.zfs_bin or "zfs") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        proc = await asyncio.create_subprocess_exec(
            self.zfs_bin or "zfs", "get", "-H", "-o", "name,property,value",
            "encryption,keyformat",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except TimeoutError:
            proc.kill()
            return
        # Each line: "<dataset>\t<property>\t<value>"
        for raw in stdout.decode("utf-8", errors="replace").splitlines():
            parts = raw.split("\t")
            if len(parts) != 3:
                continue
            dataset, prop, value = parts
            if prop != "encryption" or value in {"-", "off"}:
                continue
            # value examples: "aes-256-gcm", "aes-128-ccm"
            canonical = value.upper().replace("-CCM", "").replace("-GCM", "-GCM")
            cls = classify(canonical)
            emit(Finding(
                probe_id=self.id,
                algorithm=value,
                classification=cls,
                severity=_sev(cls),
                title=f"ZFS dataset {dataset} encryption = {value}",
                evidence={"dataset": dataset, "encryption": value},
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
