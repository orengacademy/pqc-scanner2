"""sbom.lang.maven — pom.xml + project-local M2 repo parser."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package

_DEP_RE = re.compile(
    r"<dependency>\s*"
    r"<groupId>([^<]+)</groupId>\s*"
    r"<artifactId>([^<]+)</artifactId>\s*"
    r"<version>([^<]+)</version>",
    re.DOTALL,
)


class SbomLangMaven(Probe):
    id = "sbom.lang.maven"
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
            for pom in root.rglob("pom.xml"):
                try:
                    text = pom.read_text(errors="replace")
                except OSError:
                    continue
                for m in _DEP_RE.finditer(text):
                    group, artifact, version = m.group(1), m.group(2), m.group(3)
                    emit_package(self.id, emit,
                                 name=f"{group}:{artifact}", version=version,
                                 manager="maven", purl_type="maven",
                                 extra_evidence={"path": str(pom),
                                                 "groupId": group,
                                                 "artifactId": artifact})
