"""sbom.os.pacman — Arch Linux pacman package list via /var/lib/pacman/local."""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomOsPacman(Probe):
    id = "sbom.os.pacman"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, db_root: Path | None = None):
        self.db_root = db_root or Path("/var/lib/pacman/local")

    async def applies(self, ctx: ScanContext) -> bool:
        return self.db_root.exists()

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for desc in self.db_root.glob("*/desc"):
            try:
                text = desc.read_text(errors="replace")
            except OSError:
                continue
            name = ""
            version = ""
            it = iter(text.splitlines())
            for line in it:
                if line == "%NAME%":
                    name = next(it, "").strip()
                elif line == "%VERSION%":
                    version = next(it, "").strip()
                if name and version:
                    break
            if name:
                emit_package(self.id, emit,
                             name=name, version=version,
                             manager="pacman", purl_type="pacman/arch")
