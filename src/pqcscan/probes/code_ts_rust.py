"""code.ts.rust — regex MVP for Rust (tree-sitter upgrade later)."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.srcstrip import code_finditer, strip_noncode
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source

_USE_WEAK_RE = re.compile(r"\buse\s+(md5|sha1|md4|md2)\b")
_WEAK_FUNC_RE = re.compile(r"\b(md5|sha1)\s*::\s*Md5|::Sha1|::compute|::digest", re.IGNORECASE)
_DES_RE = re.compile(r"\b(Des|TripleDes|Des3)::new\b")
_RC4_RE = re.compile(r"\bRc4::new\b")
_RSA_GEN_RE = re.compile(
    r"""RsaPrivateKey\s*::\s*new\s*\([^,)]+,\s*(\d+)""",
)


class CodeTsRust(Probe):
    id = "code.ts.rust"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in walk_source(self.roots, (".rs",)):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        scan_text = strip_noncode(text, "rust")
        for m in code_finditer(_USE_WEAK_RE, text, scan_text):
            line_no = text[: m.start()].count("\n") + 1
            alg = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"use {alg.lower()} (weak hash crate) in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in code_finditer(_DES_RE, text, scan_text):
            line_no = text[: m.start()].count("\n") + 1
            cipher = m.group(1)
            emit(Finding(
                probe_id=self.id,
                algorithm="DES" if cipher == "Des" else "3DES",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"{cipher}::new in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in code_finditer(_RC4_RE, text, scan_text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm="RC4",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"Rc4::new in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in code_finditer(_RSA_GEN_RE, text, scan_text):
            bits = int(m.group(1))
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RSA-{bits}",
                classification=cls,
                severity=Severity.CRIT if bits < 3072 else Severity.HIGH,
                title=f"RsaPrivateKey::new(.., {bits}) in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
