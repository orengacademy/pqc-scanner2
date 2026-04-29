from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_WEAK_HASH_RE = re.compile(r"hashlib\.(md5|sha1)\s*\(", re.IGNORECASE)
_EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "__pycache__",
    "vendor", "dist", "build", "target",
}


class CodeTsPython(Probe):
    """tree-sitter would parse the AST in v2.next; v1 MVP uses a regex."""

    id = "code.ts.python"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*.py"):
                if any(part in _EXCLUDE_DIRS for part in path.parts):
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                for m in _WEAK_HASH_RE.finditer(text):
                    line_no = text[: m.start()].count("\n") + 1
                    alg = m.group(1).upper()
                    snippet = text.splitlines()[line_no - 1][:120]
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=alg,
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"{alg} usage in {path}:{line_no}",
                        evidence={
                            "path": str(path),
                            "line": line_no,
                            "snippet": snippet,
                        },
                        remediation={
                            "snippet": "# replace with hashlib.sha256()",
                        },
                    ))
