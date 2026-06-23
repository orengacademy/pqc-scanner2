"""host.tpm.sealed_keys — inventory TPM-sealed volume-key bindings.

LUKS volumes can be unlocked automatically by sealing the volume key into a
TPM (via systemd-cryptenroll/tpm2-device, a tpm2 keyscript, or clevis). The TPM
performs this sealing with classical RSA/ECC primitives, so each such binding is
a piece of key-management that must be re-evaluated in the PQC era. This probe
parses /etc/crypttab and /etc/clevis (injectable) and emits one finding per
TPM-bound mapping. Pure text parse — no TPM/cryptsetup binary is invoked.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_PATHS = [
    Path("/etc/crypttab"),
    Path("/etc/clevis"),
]

# Skip pathologically large files — crypttab / binding hints are tiny.
_MAX_BYTES = 1_000_000

# crypttab options (4th field) that indicate a TPM2 sealing.
_TPM_OPTION_RE = re.compile(
    r"(?:tpm2-device\b|\btpm2\b|keyscript=[^,\s]*tpm2)", re.IGNORECASE
)

_NOTE = (
    "TPM-sealed volume key uses classical RSA/ECC sealing — "
    "track for PQC-era key management"
)


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


class HostTpmSealedKeys(Probe):
    """Inventory TPM-sealed LUKS volume-key bindings (crypttab + clevis)."""

    id = "host.tpm.sealed_keys"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(self, paths: list[Path] | None = None) -> None:
        self.paths = paths if paths is not None else _DEFAULT_PATHS

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self.paths:
            try:
                if path.is_dir():
                    self._scan_clevis_dir(path, emit)
                elif path.is_file():
                    self._scan_crypttab(path, emit)
            except OSError:
                continue

    def _scan_crypttab(self, path: Path, emit: Emitter) -> None:
        try:
            if path.stat().st_size > _MAX_BYTES:
                return
            text = path.read_text(errors="replace")
        except (OSError, ValueError):
            return
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 4:
                continue
            name, options = fields[0], fields[3]
            if not _TPM_OPTION_RE.search(options):
                continue
            self._emit(name, {"line": line, "source": str(path)}, emit)

    def _scan_clevis_dir(self, directory: Path, emit: Emitter) -> None:
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            # Binding-hint files map to a volume by their stem (e.g. luks-home.jwe).
            self._emit(entry.stem, {"path": str(entry), "source": str(directory)}, emit)

    def _emit(self, volume: str, evidence: dict, emit: Emitter) -> None:
        evidence = {"volume": volume, **evidence, "note": _NOTE}
        emit(Finding(
            probe_id=self.id,
            algorithm="TPM-sealed",
            classification=Classification.SEDERHANA,
            severity=_sev(Classification.SEDERHANA),
            title=f"TPM-sealed volume key for {volume}",
            evidence=evidence,
            remediation={
                "snippet": (
                    "# The TPM seals this volume key with classical RSA/ECC; "
                    "re-evaluate key sealing for the PQC era."
                ),
            },
        ))
