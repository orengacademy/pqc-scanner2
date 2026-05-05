"""code.ts.python — Python source-code crypto detection (regex-based MVP).

Detects:
  - hashlib.md5 / hashlib.sha1                       (Sangat Tinggi)
  - cryptography.hazmat ... rsa.generate_private_key (key_size param flagged
                                                      Sangat Tinggi if <3072,
                                                      Tinggi otherwise)
  - PyCryptodome RSA.generate(<bits>, ...)           (same)
  - DSA.generate / dsa.generate_private_key          (Sangat Tinggi)
  - DES.new / from Crypto.Cipher import DES          (Sangat Tinggi)
  - 3DES.new / Crypto.Cipher.DES3                    (Sangat Tinggi)
  - AES.new(..., AES.MODE_CBC, ...)                  (Tinggi — AES-CBC)

Tree-sitter AST parsing arrives in Plan B14; this regex pass covers the
most common patterns and ships zero new system deps.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "__pycache__",
    "vendor", "dist", "build", "target",
}

_WEAK_HASH_RE = re.compile(r"hashlib\.(md5|sha1)\s*\(", re.IGNORECASE)
_HASHLIB_NEW_RE = re.compile(
    r"hashlib\.new\s*\(\s*['\"](md5|sha1|md4|md2)['\"]", re.IGNORECASE,
)

# cryptography.hazmat — rsa.generate_private_key(public_exponent=N, key_size=BITS)
_RSA_HAZMAT_RE = re.compile(
    r"rsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(\d+)",
    re.IGNORECASE | re.DOTALL,
)
# PyCryptodome — RSA.generate(2048, ...)
_RSA_PYCRYPTO_RE = re.compile(
    r"\bRSA\.generate\s*\(\s*(\d+)", re.IGNORECASE,
)

_DSA_GEN_RE = re.compile(
    r"\b(DSA\.generate|dsa\.generate_private_key)\s*\(", re.IGNORECASE,
)
_DES_NEW_RE = re.compile(
    r"\b(DES|DES3)\.new\s*\(", re.IGNORECASE,
)
_DES_IMPORT_RE = re.compile(
    r"from\s+Crypto\.Cipher\s+import\s+(DES|DES3)\b", re.IGNORECASE,
)
_AES_CBC_RE = re.compile(
    r"AES\.new\s*\([^)]*AES\.MODE_CBC", re.IGNORECASE | re.DOTALL,
)


class CodeTsPython(Probe):
    """Regex-based Python source crypto scanner (tree-sitter in Plan B14)."""

    id = "code.ts.python"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

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
                self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        lines = text.splitlines()

        def _line_of(start: int) -> int:
            return text[:start].count("\n") + 1

        def _snippet(line_no: int) -> str:
            return lines[line_no - 1][:160] if 0 < line_no <= len(lines) else ""

        # 1. Weak hashes via hashlib.<weak>(...)
        for m in _WEAK_HASH_RE.finditer(text):
            line_no = _line_of(m.start())
            alg = m.group(1).upper()
            emit(self._mk(path, line_no, _snippet(line_no), alg,
                          Classification.SANGAT_TINGGI, Severity.CRIT,
                          f"{alg} usage via hashlib"))

        for m in _HASHLIB_NEW_RE.finditer(text):
            line_no = _line_of(m.start())
            alg = m.group(1).upper()
            emit(self._mk(path, line_no, _snippet(line_no), alg,
                          Classification.SANGAT_TINGGI, Severity.CRIT,
                          f"{alg} usage via hashlib.new()"))

        # 2. RSA generation — flag key_size.
        for m in _RSA_HAZMAT_RE.finditer(text):
            line_no = _line_of(m.start())
            bits = int(m.group(1))
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            sev = Severity.CRIT if bits < 3072 else Severity.HIGH
            emit(self._mk(path, line_no, _snippet(line_no), f"RSA-{bits}",
                          cls, sev,
                          f"cryptography.hazmat rsa.generate_private_key key_size={bits}"))

        for m in _RSA_PYCRYPTO_RE.finditer(text):
            line_no = _line_of(m.start())
            bits = int(m.group(1))
            cls = (Classification.SANGAT_TINGGI if bits < 3072
                   else Classification.TINGGI)
            sev = Severity.CRIT if bits < 3072 else Severity.HIGH
            emit(self._mk(path, line_no, _snippet(line_no), f"RSA-{bits}",
                          cls, sev, f"PyCryptodome RSA.generate({bits})"))

        # 3. DSA generation — always Sangat Tinggi (DSA broken).
        for m in _DSA_GEN_RE.finditer(text):
            line_no = _line_of(m.start())
            emit(self._mk(path, line_no, _snippet(line_no), "DSA",
                          Classification.SANGAT_TINGGI, Severity.CRIT,
                          "DSA key generation"))

        # 4. DES / 3DES — Sangat Tinggi.
        for m in _DES_NEW_RE.finditer(text):
            line_no = _line_of(m.start())
            cipher = m.group(1).upper()
            canonical = "3DES" if cipher == "DES3" else "DES"
            emit(self._mk(path, line_no, _snippet(line_no), canonical,
                          Classification.SANGAT_TINGGI, Severity.CRIT,
                          f"{canonical} cipher .new() call"))
        for m in _DES_IMPORT_RE.finditer(text):
            line_no = _line_of(m.start())
            cipher = m.group(1).upper()
            canonical = "3DES" if cipher == "DES3" else "DES"
            emit(self._mk(path, line_no, _snippet(line_no), canonical,
                          Classification.SANGAT_TINGGI, Severity.CRIT,
                          f"import of Crypto.Cipher.{cipher}"))

        # 5. AES-CBC mode — Tinggi (prefer GCM).
        for m in _AES_CBC_RE.finditer(text):
            line_no = _line_of(m.start())
            emit(self._mk(path, line_no, _snippet(line_no), "AES-CBC",
                          Classification.TINGGI, Severity.HIGH,
                          "AES-CBC mode (prefer AES-GCM)"))

    def _mk(self, path: Path, line_no: int, snippet: str, algorithm: str,
            classification: Classification, severity: Severity,
            description: str) -> Finding:
        return Finding(
            probe_id=self.id,
            algorithm=algorithm,
            classification=classification,
            severity=severity,
            title=f"{description} in {path}:{line_no}",
            evidence={
                "path": str(path),
                "line": line_no,
                "snippet": snippet,
            },
            remediation={
                "snippet": "# Replace with FIPS 203/204/205 family or AES-256-GCM",
            },
        )
