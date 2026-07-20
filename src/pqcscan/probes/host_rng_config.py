"""host.rng.config — kernel entropy pool / hardware RNG posture.

Every key a host generates is only as strong as the randomness beneath it: a
starved entropy pool or a purely software-seeded DRBG is a classic source of
weak keys. This probe reads the kernel's entropy estimate, checks whether a
hardware RNG backs the pool (/sys/class/misc/hw_random/rng_current) and looks
for a userspace entropy daemon (rngd / haveged). Best-effort reads only — a
missing file simply skips that check.
"""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# Below this the kernel pool is considered starved (fully-seeded is 256+).
_ENTROPY_FLOOR = 256

_DEFAULT_DAEMON_PATHS = [
    Path("/usr/sbin/rngd"),
    Path("/usr/sbin/haveged"),
]


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


class HostRngConfig(Probe):
    """Report weak host RNG posture: low entropy, no hardware RNG, no daemon."""

    id = "host.rng.config"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(
        self,
        entropy_path: Path | None = None,
        hwrng_path: Path | None = None,
        rng_daemon_paths: list[Path] | None = None,
    ) -> None:
        self.entropy_path = entropy_path or Path("/proc/sys/kernel/random/entropy_avail")
        self.hwrng_path = hwrng_path or Path("/sys/class/misc/hw_random/rng_current")
        self.rng_daemon_paths = (
            rng_daemon_paths if rng_daemon_paths is not None else _DEFAULT_DAEMON_PATHS
        )

    async def applies(self, ctx: ScanContext) -> bool:
        return self.entropy_path.exists() or self.hwrng_path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        self._check_entropy(emit)
        hw_present = self._check_hw_random(emit)
        if not hw_present and not any(p.exists() for p in self.rng_daemon_paths):
            emit(Finding(
                probe_id=self.id,
                algorithm="rng/daemon",
                classification=Classification.INFO,
                severity=_sev(Classification.INFO),
                title="No entropy daemon (rngd/haveged) and no hardware RNG",
                evidence={
                    "daemon_paths_checked": [str(p) for p in self.rng_daemon_paths],
                    "note": "Entropy relies solely on the kernel's software sources.",
                },
                remediation={
                    "snippet": "# Consider an entropy daemon on entropy-starved hosts:\n"
                               "sudo apt install rng-tools   # or: haveged",
                },
            ))

    def _check_entropy(self, emit: Emitter) -> None:
        try:
            value = int(self.entropy_path.read_text(errors="replace").strip())
        except (OSError, ValueError):
            return
        if value < _ENTROPY_FLOOR:
            emit(Finding(
                probe_id=self.id,
                algorithm="rng/entropy",
                classification=Classification.SEDERHANA,
                severity=_sev(Classification.SEDERHANA),
                title=f"Low kernel entropy pool ({value} < {_ENTROPY_FLOOR})",
                evidence={
                    "path": str(self.entropy_path),
                    "entropy_avail": value,
                    "note": "A starved entropy pool weakens every key generated on this host.",
                },
                remediation={
                    "snippet": "# Feed the pool with a hardware RNG or an entropy daemon:\n"
                               "sudo apt install rng-tools   # or: haveged",
                },
            ))

    def _check_hw_random(self, emit: Emitter) -> bool:
        """Emit an informational finding when no hardware RNG backs the pool.

        Returns True when a hardware RNG is present.
        """
        try:
            current = self.hwrng_path.read_text(errors="replace").strip()
        except OSError:
            current = ""
        if current and current.lower() != "none":
            return True
        emit(Finding(
            probe_id=self.id,
            algorithm="rng/hw_random",
            classification=Classification.INFO,
            severity=_sev(Classification.INFO),
            title="No hardware RNG backing the entropy pool",
            evidence={
                "path": str(self.hwrng_path),
                "rng_current": current or "absent",
            },
        ))
        return False
