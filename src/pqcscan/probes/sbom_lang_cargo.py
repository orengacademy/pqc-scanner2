"""sbom.lang.cargo — Rust Cargo.lock parser (pure Python, no `cargo` needed)."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package


# Cargo.lock entries are TOML stanzas:
#   [[package]]
#   name = "serde"
#   version = "1.0.197"
_PKG_BLOCK_RE = re.compile(
    r"\[\[package\]\][^\[]*?name\s*=\s*\"([^\"]+)\"[^\[]*?version\s*=\s*\"([^\"]+)\"",
    re.DOTALL,
)


class SbomLangCargo(Probe):
    id = "sbom.lang.cargo"
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
            for lock in root.rglob("Cargo.lock"):
                try:
                    text = lock.read_text(errors="replace")
                except OSError:
                    continue
                for m in _PKG_BLOCK_RE.finditer(text):
                    name, version = m.group(1), m.group(2)
                    emit_package(self.id, emit,
                                 name=name, version=version,
                                 manager="cargo", purl_type="cargo",
                                 extra_evidence={"path": str(lock)})
