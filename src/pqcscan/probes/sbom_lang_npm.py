"""sbom.lang.npm — parse package.json + node_modules/*/package.json."""
from __future__ import annotations

import json
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomLangNpm(Probe):
    id = "sbom.lang.npm"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for pkg_json in root.rglob("package.json"):
                # Skip nested node_modules to avoid combinatorial blowup.
                parts = pkg_json.parts
                if parts.count("node_modules") > 1:
                    continue
                try:
                    data = json.loads(pkg_json.read_text(errors="replace"))
                except (OSError, json.JSONDecodeError):
                    continue
                name = data.get("name", "")
                version = data.get("version", "")
                if name:
                    emit_package(self.id, emit,
                                 name=name, version=version,
                                 manager="npm", purl_type="npm",
                                 extra_evidence={"path": str(pkg_json)})
