"""hw.tpm.algorithms — TPM 2.0 active PCR banks + version (Linux sysfs).

Reads /sys/class/tpm/tpm*/active_pcr_banks + /tpm_version_major.
SHA-1 PCR banks are flagged TINGGI; TPM 1.2 is flagged TINGGI (legacy).
"""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class HwTpmAlgorithms(Probe):
    id = "hw.tpm.algorithms"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:hw", "bukukerja:hw", "mykripto:hw")

    def __init__(self, sysfs_root: Path | None = None):
        # Override for testing; production reads from /sys/class/tpm.
        self.sysfs_root = sysfs_root or Path("/sys/class/tpm")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.sysfs_root.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        if not self.sysfs_root.exists():
            return
        for tpm_dir in sorted(self.sysfs_root.glob("tpm*")):
            if not tpm_dir.is_dir():
                continue
            self._scan_tpm(tpm_dir, emit)

    def _scan_tpm(self, tpm_dir: Path, emit: Emitter) -> None:
        device = tpm_dir.name

        version_path = tpm_dir / "tpm_version_major"
        if version_path.is_file():
            try:
                version = version_path.read_text().strip()
            except OSError:
                version = ""
            if version == "1":
                emit(Finding(
                    probe_id=self.id, algorithm="TPM-1.2",
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"Legacy TPM 1.2 detected at {device}",
                    evidence={"device": device, "path": str(version_path),
                              "version": version},
                ))
            elif version == "2":
                emit(Finding(
                    probe_id=self.id, algorithm="TPM-2.0",
                    classification=Classification.INFO, severity=Severity.INFO,
                    title=f"TPM 2.0 present at {device}",
                    evidence={"device": device, "path": str(version_path),
                              "version": version},
                ))

        banks_path = tpm_dir / "active_pcr_banks"
        if banks_path.is_file():
            try:
                banks = banks_path.read_text().split()
            except OSError:
                banks = []
            for bank in banks:
                norm = bank.strip().lower()
                if norm == "sha1":
                    emit(Finding(
                        probe_id=self.id, algorithm="TPM-PCR-SHA1",
                        classification=Classification.TINGGI,
                        severity=Severity.HIGH,
                        title=f"TPM SHA-1 PCR bank active on {device}",
                        evidence={"device": device, "path": str(banks_path),
                                  "bank": norm},
                    ))
                else:
                    emit(Finding(
                        probe_id=self.id, algorithm=f"TPM-PCR-{norm.upper()}",
                        classification=Classification.INFO,
                        severity=Severity.INFO,
                        title=f"TPM PCR bank {norm} active on {device}",
                        evidence={"device": device, "path": str(banks_path),
                                  "bank": norm},
                    ))
