from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


class HostSshModuli(Probe):
    id = "host.ssh.moduli"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:ssh", "bukukerja:ssh", "mykripto:ssh")

    def __init__(self, path: Path | None = None):
        self.path = path or Path("/etc/ssh/moduli")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            text = self.path.read_text(errors="replace")
        except OSError:
            return

        sizes: list[int] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cols = line.split()
            if len(cols) < 5:
                continue
            try:
                sizes.append(int(cols[4]))
            except ValueError:
                continue

        if not sizes:
            return

        # Column 5 stores the prime size minus one (e.g. 2047 for the 2048-bit
        # group); classify on the actual prime size but report the raw value.
        min_bits = min(sizes)
        if min_bits + 1 >= 3072:
            return

        cls = Classification.SANGAT_TINGGI if min_bits + 1 < 2048 else Classification.TINGGI
        weak_line_count = sum(1 for s in sizes if s + 1 < 3072)
        emit(Finding(
            probe_id=self.id,
            algorithm=f"DH-{min_bits}",
            classification=cls,
            severity=sev_for(cls),
            title=f"sshd moduli offers {min_bits}-bit DH group-exchange groups",
            evidence={
                "path": str(self.path),
                "min_bits": min_bits,
                "weak_line_count": weak_line_count,
            },
            remediation={"snippet": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe"},
        ))


