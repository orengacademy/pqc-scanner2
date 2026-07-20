"""code.ts.python — Python source-code crypto detection (stdlib-`ast` engine).

Primary engine: `pqcscan.core.pyast`, which parses each file with Python's
stdlib `ast` module and walks the true syntax tree. Because it sees code and
not text, crypto tokens inside comments (`# hashlib.md5()`) and string literals
(`x = "hashlib.md5()"`) produce ZERO findings — the false positives the old
regex pass could not avoid. Imports/aliases are resolved so detection is
name-accurate. AST-confirmed findings are structured facts → confidence "high".

Fallback: when a file is not valid Python 3 (Python-2 sources, Jinja/templated
snippets, partial fragments) `ast.parse` raises `SyntaxError`; for those files
only, we fall back to the legacy regex scan so nothing is lost. Regex hits keep
the central model's "medium" confidence for `code.*`.

Detected patterns:
  - hashlib.md5 / sha1 / new("md5"|"sha1"|"md4"|"md2")   (Sangat Tinggi)
  - rsa.generate_private_key / RSA.generate — key_size    (Sangat Tinggi <3072,
                                                            Tinggi otherwise)
  - dsa.generate_private_key / DSA.generate               (Sangat Tinggi)
  - ec.generate_private_key (classical EC)                (Tinggi)
  - DES / DES3 / ARC4 / Blowfish .new(), algorithms.*     (Sangat Tinggi)
  - AES.new(..., AES.MODE_CBC) / modes.CBC(...)           (Tinggi — AES-CBC)
  - ssl.PROTOCOL_TLSv1 / TLSv1_1 / SSLv3 / SSLv23         (Sangat Tinggi / Tinggi)
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core import pyast
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "__pycache__",
    "vendor", "dist", "build", "target",
}

# ------------------------------------------------------------------------
# kind -> (Classification, Severity). Kept in the probe so pyast stays a pure
# detector. rsa_keygen and weak_tls_proto depend on the algorithm string, so
# they are resolved dynamically in _classify().
# ------------------------------------------------------------------------
_STATIC_KIND_MAP: dict[str, tuple[Classification, Severity]] = {
    "weak_hash": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "dsa_keygen": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "ecdsa_keygen": (Classification.TINGGI, Severity.HIGH),
    "des_cipher": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "rc4_cipher": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "blowfish_cipher": (Classification.SANGAT_TINGGI, Severity.CRIT),
    "aes_cbc": (Classification.TINGGI, Severity.HIGH),
}
# TLS protocol constants Sangat Tinggi except SSLv23 (negotiates down) = Tinggi.
_TLS_HIGH_ONLY = {"SSLv23"}


def _classify(hit: pyast.AstHit) -> tuple[Classification, Severity]:
    if hit.kind == "rsa_keygen":
        bits = _rsa_bits(hit.algorithm)
        if bits is not None and bits >= 3072:
            return Classification.TINGGI, Severity.HIGH
        if bits is None:
            # Non-literal key_size — cannot prove strength; match TINGGI/HIGH.
            return Classification.TINGGI, Severity.HIGH
        return Classification.SANGAT_TINGGI, Severity.CRIT
    if hit.kind == "weak_tls_proto":
        if hit.algorithm in _TLS_HIGH_ONLY:
            return Classification.TINGGI, Severity.HIGH
        return Classification.SANGAT_TINGGI, Severity.CRIT
    return _STATIC_KIND_MAP.get(hit.kind, (Classification.TINGGI, Severity.HIGH))


def _rsa_bits(algorithm: str) -> int | None:
    if algorithm.startswith("RSA-"):
        try:
            return int(algorithm.split("-", 1)[1])
        except ValueError:
            return None
    return None


# ------------------------------------------------------------------------
# Legacy regex fallback (only used when ast.parse raises SyntaxError).
# ------------------------------------------------------------------------
_WEAK_HASH_RE = re.compile(r"hashlib\.(md5|sha1)\s*\(", re.IGNORECASE)
_HASHLIB_NEW_RE = re.compile(
    r"hashlib\.new\s*\(\s*['\"](md5|sha1|md4|md2)['\"]", re.IGNORECASE,
)
_RSA_HAZMAT_RE = re.compile(
    r"rsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(\d+)",
    re.IGNORECASE | re.DOTALL,
)
_RSA_PYCRYPTO_RE = re.compile(r"\bRSA\.generate\s*\(\s*(\d+)", re.IGNORECASE)
_DSA_GEN_RE = re.compile(
    r"\b(DSA\.generate|dsa\.generate_private_key)\s*\(", re.IGNORECASE,
)
_DES_NEW_RE = re.compile(r"\b(DES|DES3)\.new\s*\(", re.IGNORECASE)
_DES_IMPORT_RE = re.compile(
    r"from\s+Crypto\.Cipher\s+import\s+(DES|DES3)\b", re.IGNORECASE,
)
_AES_CBC_RE = re.compile(
    r"AES\.new\s*\([^)]*AES\.MODE_CBC", re.IGNORECASE | re.DOTALL,
)


class CodeTsPython(Probe):
    """AST-based Python source crypto scanner (regex fallback for bad parses)."""

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
                self._scan_file(text, path, emit)

    # -- per-file dispatch -----------------------------------------------

    def _scan_file(self, text: str, path: Path, emit: Emitter) -> None:
        try:
            hits = pyast.analyze(text)
        except SyntaxError:
            # Not valid Python 3 — fall back to regex so nothing is lost.
            self._scan_text_regex(text, path, emit)
            return
        self._emit_ast_hits(text, path, hits, emit)

    def _emit_ast_hits(self, text: str, path: Path, hits: list[pyast.AstHit],
                       emit: Emitter) -> None:
        lines = text.splitlines()

        def _snippet(line_no: int) -> str:
            return lines[line_no - 1][:160] if 0 < line_no <= len(lines) else ""

        for hit in hits:
            classification, severity = _classify(hit)
            emit(Finding(
                probe_id=self.id,
                algorithm=hit.algorithm,
                classification=classification,
                severity=severity,
                title=f"{hit.detail} in {path}:{hit.lineno}",
                evidence={
                    "file": str(path),
                    "line": hit.lineno,
                    "snippet": _snippet(hit.lineno),
                    "kind": hit.kind,
                    # AST facts are structured → force high confidence.
                    "confidence": "high",
                },
                remediation={
                    "snippet": "# Replace with FIPS 203/204/205 family or AES-256-GCM",
                },
            ))

    # -- regex fallback ---------------------------------------------------

    def _scan_text_regex(self, text: str, path: Path, emit: Emitter) -> None:
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
        # No forced confidence: the central model returns "medium" for code.*
        # regex hits (and "low" inside comments/tests/vendored trees).
        return Finding(
            probe_id=self.id,
            algorithm=algorithm,
            classification=classification,
            severity=severity,
            title=f"{description} in {path}:{line_no}",
            evidence={
                "file": str(path),
                "line": line_no,
                "snippet": snippet,
            },
            remediation={
                "snippet": "# Replace with FIPS 203/204/205 family or AES-256-GCM",
            },
        )
