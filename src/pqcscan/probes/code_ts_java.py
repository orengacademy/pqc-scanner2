"""code.ts.java — regex MVP for Java/Kotlin (tree-sitter upgrade later)."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source

_WEAK_DIGEST_RE = re.compile(
    r"""MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["']""",
    re.IGNORECASE,
)
_CIPHER_RE = re.compile(
    r"""Cipher\.getInstance\s*\(\s*["']([A-Za-z0-9/_\-]+)["']""",
    re.IGNORECASE,
)
_RSA_INIT_RE = re.compile(
    r"""KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']\s*\)[\s\S]{0,200}?\.initialize\s*\(\s*(\d+)""",
    re.IGNORECASE,
)
_DSA_INST_RE = re.compile(
    r"""KeyPairGenerator\.getInstance\s*\(\s*["']DSA["']""",
    re.IGNORECASE,
)


class CodeTsJava(Probe):
    id = "code.ts.java"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in walk_source(self.roots, (".java", ".kt", ".scala")):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        for m in _WEAK_DIGEST_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            alg = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"MessageDigest {alg} in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _CIPHER_RE.finditer(text):
            spec = m.group(1)
            up = spec.upper()
            line_no = text[: m.start()].count("\n") + 1
            if ("DES" in up and "DESEDE" not in up and "AES" not in up) or "DESEDE" in up or "3DES" in up or "RC4" in up or "RC2" in up:  # noqa: E501
                cls, sev = Classification.SANGAT_TINGGI, Severity.CRIT
            elif "/CBC/" in up:
                cls, sev = Classification.TINGGI, Severity.HIGH
            elif "/ECB/" in up:
                cls, sev = Classification.SANGAT_TINGGI, Severity.CRIT
            else:
                continue
            emit(Finding(
                probe_id=self.id,
                algorithm=spec,
                classification=cls, severity=sev,
                title=f"Cipher.getInstance({spec!r}) in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _RSA_INIT_RE.finditer(text):
            bits = int(m.group(1))
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RSA-{bits}",
                classification=cls,
                severity=Severity.CRIT if bits < 3072 else Severity.HIGH,
                title=f"KeyPairGenerator RSA initialize({bits}) in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _DSA_INST_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm="DSA",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"KeyPairGenerator DSA in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
