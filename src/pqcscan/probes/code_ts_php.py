"""code.ts.php — regex MVP for PHP (tree-sitter upgrade later)."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source


# PHP built-in md5() / sha1() / hash('md5'|'sha1', ...).
_WEAK_HASH_RE = re.compile(r"\b(md5|sha1)\s*\(", re.IGNORECASE)
_HASH_FUNC_RE = re.compile(
    r"""\bhash\s*\(\s*['"](md5|md4|md2|sha1|haval)['"]""",
    re.IGNORECASE,
)
_MCRYPT_RE = re.compile(r"\bmcrypt_[a-z_]+\s*\(", re.IGNORECASE)
_OPENSSL_RSA_RE = re.compile(
    r"""private_key_bits['"]?\s*=>\s*(\d+)""",
    re.IGNORECASE,
)


class CodeTsPhp(Probe):
    id = "code.ts.php"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in walk_source(self.roots, (".php", ".phtml", ".phar")):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        for m in _WEAK_HASH_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            fn = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=fn,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"{fn}() built-in in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _HASH_FUNC_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            alg = m.group(1).upper()
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"hash('{alg.lower()}', ...) in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
        for m in _MCRYPT_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm="MCRYPT",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"deprecated mcrypt_* function in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
                remediation={"snippet": "// Replace with openssl_* or sodium_*"},
            ))
        for m in _OPENSSL_RSA_RE.finditer(text):
            bits = int(m.group(1))
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RSA-{bits}",
                classification=cls,
                severity=Severity.CRIT if bits < 3072 else Severity.HIGH,
                title=f"openssl_pkey_new private_key_bits={bits} in {path}:{line_no}",
                evidence={"path": str(path), "line": line_no},
            ))
