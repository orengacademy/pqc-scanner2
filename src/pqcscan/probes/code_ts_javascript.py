"""code.ts.javascript — regex MVP for JS/TS (tree-sitter upgrade later)."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.srcstrip import code_finditer, strip_noncode
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source

_WEAK_HASH_RE = re.compile(
    r"""crypto\.createHash\s*\(\s*['"](md5|sha1)['"]""",
    re.IGNORECASE,
)
_WEAK_CIPHER_RE = re.compile(
    r"""crypto\.createCipher(?:iv)?\s*\(\s*['"](des|3des|des-ede3|rc4)""",
    re.IGNORECASE,
)
_RSA_GEN_RE = re.compile(
    r"""generateKeyPair(?:Sync)?\s*\(\s*['"]rsa['"][^)]*modulusLength\s*:\s*(\d+)""",
    re.IGNORECASE | re.DOTALL,
)
_JWT_HS_RE = re.compile(
    r"""jwt\.sign\s*\([^)]*algorithm\s*:\s*['"](HS\d+|RS\d+|ES\d+|none)['"]""",
    re.IGNORECASE | re.DOTALL,
)


class CodeTsJavascript(Probe):
    id = "code.ts.javascript"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in walk_source(self.roots, (".js", ".ts", ".mjs", ".cjs")):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        scan_text = strip_noncode(text, "javascript")
        for m in code_finditer(_WEAK_HASH_RE, text, scan_text):
            line_no = text[: m.start()].count("\n") + 1
            alg = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"{alg} via crypto.createHash in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in code_finditer(_WEAK_CIPHER_RE, text, scan_text):
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
        for m in code_finditer(_RSA_GEN_RE, text, scan_text):
            bits = int(m.group(1))
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            sev = Severity.CRIT if bits < 3072 else Severity.HIGH
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RSA-{bits}",
                classification=cls, severity=sev,
                title=f"crypto.generateKeyPair RSA modulusLength={bits} in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in code_finditer(_JWT_HS_RE, text, scan_text):
            alg = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SANGAT_TINGGI if alg.lower() == "none"
                   else Classification.TINGGI)
            emit(Finding(
                probe_id=self.id,
                algorithm=f"JWT-{alg}",
                classification=cls,
                severity=Severity.HIGH if cls is Classification.TINGGI else Severity.CRIT,
                title=f"jwt.sign algorithm={alg} in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
