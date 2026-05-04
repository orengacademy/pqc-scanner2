"""code.ts.go — regex MVP for Go (tree-sitter upgrade later)."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source


_WEAK_HASH_RE = re.compile(r"\b(md5|sha1)\.(?:New|Sum)\b")
_WEAK_CIPHER_RE = re.compile(r"\b(des|rc4)\.NewCipher\b")
_RSA_GEN_RE = re.compile(r"\brsa\.GenerateKey\s*\([^,]+,\s*(\d+)\s*\)")
_DSA_GEN_RE = re.compile(r"\bdsa\.GenerateParameters\s*\(")


class CodeTsGo(Probe):
    id = "code.ts.go"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in walk_source(self.roots, (".go",)):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        for m in _WEAK_HASH_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            alg = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"{alg} via {alg.lower()}.New/Sum in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _WEAK_CIPHER_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            cipher = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=cipher,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"{cipher} cipher in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _RSA_GEN_RE.finditer(text):
            bits = int(m.group(1))
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            sev = Severity.CRIT if bits < 3072 else Severity.HIGH
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RSA-{bits}",
                classification=cls, severity=sev,
                title=f"rsa.GenerateKey({bits}) in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _DSA_GEN_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm="DSA",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"dsa.GenerateParameters in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
