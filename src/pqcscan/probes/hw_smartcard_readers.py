"""hw.smartcard.readers — OpenSC config (smartcard / PIV / PKCS#15).

Reads /etc/opensc.conf and flags small default RSA key lengths
(<3072 = SANGAT_TINGGI per spec Appendix B).
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_KEYLEN_RE = re.compile(
    r"\bdefault_key_length\s*=\s*(\d+)",
    re.IGNORECASE,
)
_NAMES = {"opensc.conf"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class HwSmartcardReaders(Probe):
    id = "hw.smartcard.readers"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:hw", "bukukerja:hw", "mykripto:hw")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc"), Path("/etc/opensc")]

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
                if path.name not in _NAMES:
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _KEYLEN_RE.finditer(text):
            n = int(m.group(1))
            line_no = text[: m.start()].count("\n") + 1
            if n < 3072:
                cls = Classification.SANGAT_TINGGI
                sev = Severity.CRIT
            else:
                cls = Classification.INFO
                sev = Severity.INFO
            emit(Finding(
                probe_id=self.id,
                algorithm=f"OpenSC-default_key_length={n}",
                classification=cls, severity=sev,
                title=(f"OpenSC default_key_length={n} "
                       f"in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": "default_key_length", "bits": n},
            ))
