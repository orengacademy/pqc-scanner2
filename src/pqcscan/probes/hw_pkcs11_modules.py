"""hw.pkcs11.modules — installed PKCS#11 providers (p11-kit module files).

Lists installed providers from /etc/pkcs11/modules/*.module. Each finding
is INFO; downstream consumers can correlate with the framework engine to
flag deprecated HSM software lists.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_MODULE_RE = re.compile(
    r"^\s*module\s*:\s*(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class HwPkcs11Modules(Probe):
    id = "hw.pkcs11.modules"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:hw", "bukukerja:hw", "mykripto:hw")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/pkcs11/modules"),
                               Path("/usr/share/p11-kit/modules")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            walker = [root] if root.is_file() else list(root.rglob("*"))
            for path in walker:
                if not path.is_file():
                    continue
                if any(part in _EXCLUDE_DIRS for part in path.parts):
                    continue
                if not path.name.endswith(".module"):
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _MODULE_RE.finditer(text):
            so_path = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm=f"PKCS11/{Path(so_path).name}",
                classification=Classification.INFO, severity=Severity.INFO,
                title=(f"PKCS#11 provider {Path(so_path).name} "
                       f"in {path.name}:{line_no}"),
                evidence={"module_file": str(path), "line": line_no,
                          "so_path": so_path},
            ))
