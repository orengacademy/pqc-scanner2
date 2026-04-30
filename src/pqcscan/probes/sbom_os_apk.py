"""sbom.os.apk — Alpine Linux installed-package list at /lib/apk/db/installed."""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomOsApk(Probe):
    id = "sbom.os.apk"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or Path("/lib/apk/db/installed")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.db_path.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        try:
            text = self.db_path.read_text(errors="replace")
        except OSError:
            return
        # Each package is a stanza separated by blank lines.
        # Lines: "P:name", "V:version", "S:size", etc.
        for stanza in text.split("\n\n"):
            name = ""
            version = ""
            for line in stanza.splitlines():
                if line.startswith("P:"):
                    name = line[2:].strip()
                elif line.startswith("V:"):
                    version = line[2:].strip()
            if name:
                emit_package(self.id, emit,
                             name=name, version=version,
                             manager="apk", purl_type="apk/alpine")
