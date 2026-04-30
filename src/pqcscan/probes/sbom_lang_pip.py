"""sbom.lang.pip — discover installed Python packages via dist-info METADATA."""
from __future__ import annotations

import sys
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomLangPip(Probe):
    id = "sbom.lang.pip"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, site_packages: list[Path] | None = None):
        if site_packages is not None:
            self.site_packages = site_packages
        else:
            self.site_packages = [Path(p) for p in sys.path if "site-packages" in p]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.site_packages)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for sp in self.site_packages:
            if not sp.exists():
                continue
            for distinfo in sp.glob("*.dist-info"):
                metadata = distinfo / "METADATA"
                if not metadata.exists():
                    continue
                name = ""
                version = ""
                try:
                    with metadata.open(errors="replace") as f:
                        for line in f:
                            if line.startswith("Name: "):
                                name = line[6:].strip()
                            elif line.startswith("Version: "):
                                version = line[9:].strip()
                            if name and version:
                                break
                except OSError:
                    continue
                if name:
                    emit_package(self.id, emit,
                                 name=name, version=version,
                                 manager="pip", purl_type="pypi")
