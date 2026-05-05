"""sbom.lang.gomod — parse go.mod for module + require directives."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package

_MODULE_RE = re.compile(r"^module\s+(\S+)", re.MULTILINE)
_REQUIRE_RE = re.compile(
    r"^\s*(\S+)\s+(v\d[\w.\-+/]*)\s*(?://.*)?$", re.MULTILINE,
)


class SbomLangGomod(Probe):
    id = "sbom.lang.gomod"
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
            for go_mod in root.rglob("go.mod"):
                try:
                    text = go_mod.read_text(errors="replace")
                except OSError:
                    continue
                # Module itself.
                m = _MODULE_RE.search(text)
                if m:
                    emit_package(self.id, emit,
                                 name=m.group(1), version="",
                                 manager="gomod", purl_type="golang",
                                 extra_evidence={"path": str(go_mod), "role": "module"})
                # Required deps.
                for req in _REQUIRE_RE.finditer(text):
                    dep_name, dep_ver = req.group(1), req.group(2)
                    if dep_name == m.group(1) if m else False:
                        continue
                    emit_package(self.id, emit,
                                 name=dep_name, version=dep_ver,
                                 manager="gomod", purl_type="golang",
                                 extra_evidence={"path": str(go_mod), "role": "require"})
