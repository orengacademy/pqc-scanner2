from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class SbomOsDpkg(Probe):
    id = "sbom.os.dpkg"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, status_path: Path | None = None):
        self.status_path = status_path or Path("/var/lib/dpkg/status")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.status_path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        text = self.status_path.read_text(errors="replace")
        for stanza in text.split("\n\n"):
            name = ""
            version = ""
            installed = False
            for line in stanza.splitlines():
                if line.startswith("Package: "):
                    name = line[9:].strip()
                elif line.startswith("Version: "):
                    version = line[9:].strip()
                elif line.startswith("Status: ") and "installed" in line:
                    installed = True
            if name and installed:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"package: {name} {version}",
                    evidence={
                        "name": name,
                        "version": version,
                        "manager": "dpkg",
                        "purl": f"pkg:deb/{name}@{version}",
                    },
                ))
