"""sbom.lang.composer — PHP composer.json + composer.lock parser."""
from __future__ import annotations

import json
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


class SbomLangComposer(Probe):
    id = "sbom.lang.composer"
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
            # composer.lock is the source of truth (resolved versions).
            for lock in root.rglob("composer.lock"):
                if "vendor" in lock.parts:
                    continue
                try:
                    doc = json.loads(lock.read_text(errors="replace"))
                except (OSError, json.JSONDecodeError):
                    continue
                for pkg in (doc.get("packages", []) or []) + (doc.get("packages-dev", []) or []):
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    if name:
                        emit_package(self.id, emit,
                                     name=name, version=version,
                                     manager="composer", purl_type="composer",
                                     extra_evidence={"path": str(lock)})
            # Fallback to composer.json (declared, may be unresolved).
            for spec in root.rglob("composer.json"):
                if "vendor" in spec.parts:
                    continue
                try:
                    doc = json.loads(spec.read_text(errors="replace"))
                except (OSError, json.JSONDecodeError):
                    continue
                for name, constraint in (doc.get("require", {}) or {}).items():
                    emit_package(self.id, emit,
                                 name=name, version=constraint,
                                 manager="composer", purl_type="composer",
                                 extra_evidence={"path": str(spec), "source": "require"})
