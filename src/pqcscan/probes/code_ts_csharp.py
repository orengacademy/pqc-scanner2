"""code.ts.csharp — regex MVP for C# / .NET (tree-sitter upgrade later).

Closes the ASP.NET Core (C#) source gap: the binary/SBOM probes see linked
crypto libraries, but message-level primitive calls in the application code
(RSA/DSA/EC key generation, weak hashes and ciphers, ECB mode) live in .cs
sources. Anchored on the .NET crypto *API identifier* rather than on any
string argument, so `strip_noncode` blanking of literals never hides a call
whose start sits on real code — while genuine comment/string mentions are
dropped (see ``code_finditer``).
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.srcstrip import code_finditer, strip_noncode
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source

# Weak-hash factory / ctor: MD5.Create(), new SHA1Managed(),
# new MD5CryptoServiceProvider().
_WEAK_HASH_RE = re.compile(
    r"\b(MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)?\.Create\s*\("
    r"|\bnew\s+(MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)\s*\(",
)
# Named create with the algorithm in a string: HashAlgorithm.Create("MD5"),
# CryptoConfig.CreateFromName("SHA1"). Anchor is the class name (real code).
_WEAK_HASH_NAMED_RE = re.compile(
    r"(?:HashAlgorithm|CryptoConfig|CryptoConfig\.CreateFromName)"
    r"\.(?:Create|CreateFromName)\s*\(\s*[\"'](MD5|SHA-?1)[\"']",
    re.IGNORECASE,
)
# Weak block/stream ciphers: new DESCryptoServiceProvider(), TripleDES.Create(),
# new RC2CryptoServiceProvider().
_WEAK_CIPHER_RE = re.compile(
    r"\bnew\s+(DES|TripleDES|RC2)(?:CryptoServiceProvider|Cng|Managed)?\s*\("
    r"|\b(DES|TripleDES|RC2)\.Create\s*\(",
)
# RSA with an explicit modulus: new RSACryptoServiceProvider(2048), RSA.Create(2048).
_RSA_SIZED_RE = re.compile(
    r"\b(?:new\s+RSACryptoServiceProvider|RSA(?:Cng)?\.Create)\s*\(\s*(\d+)",
)
# RSA with no explicit size (defaults to a quantum-forgeable 2048-bit key).
_RSA_BARE_RE = re.compile(
    r"\b(?:new\s+RSACryptoServiceProvider|RSA(?:Cng)?\.Create)\s*\(\s*\)",
)
# DSA (dead regardless of size).
_DSA_RE = re.compile(r"\b(?:new\s+DSACryptoServiceProvider|DSA(?:Cng)?\.Create)\s*\(")
# Elliptic curve — Shor-broken (quantum), so TINGGI.
_EC_RE = re.compile(
    r"\b(ECDsa|ECDiffieHellman)(?:Cng)?\.Create\s*\("
    r"|\bnew\s+(ECDsaCng|ECDiffieHellmanCng)\s*\(",
)
# Block-cipher mode weaknesses.
_ECB_RE = re.compile(r"\bCipherMode\.ECB\b")
_CBC_RE = re.compile(r"\bCipherMode\.CBC\b")


def _group(m: re.Match) -> str:
    """First non-None capture group, upper-cased."""
    for g in m.groups():
        if g:
            return str(g).upper()
    return str(m.group(0)).upper()


class CodeTsCsharp(Probe):
    id = "code.ts.csharp"
    family = ProbeFamily.CODE
    framework_tags = ("bukukerja:code", "mykripto:code", "nist-ir-8547:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in walk_source(self.roots, (".cs",)):
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        scan_text = strip_noncode(text, "csharp")

        def _line(m: re.Match) -> int:
            return text[: m.start()].count("\n") + 1

        def _emit(alg: str, cls: Classification, sev: Severity, m: re.Match, what: str) -> None:
            emit(Finding(
                probe_id=self.id, algorithm=alg,
                classification=cls, severity=sev,
                title=f"{what} in {path}:{_line(m)}",
                evidence={"path": str(path), "line": _line(m)},
            ))

        for m in code_finditer(_WEAK_HASH_RE, text, scan_text):
            alg = _group(m)
            _emit(alg, Classification.SANGAT_TINGGI, Severity.CRIT, m, f"weak hash {alg}")
        for m in code_finditer(_WEAK_HASH_NAMED_RE, text, scan_text):
            alg = m.group(1).upper().replace("SHA-1", "SHA1")
            _emit(alg, Classification.SANGAT_TINGGI, Severity.CRIT, m, f"weak hash {alg}")
        for m in code_finditer(_WEAK_CIPHER_RE, text, scan_text):
            alg = _group(m)
            _emit(alg, Classification.SANGAT_TINGGI, Severity.CRIT, m, f"weak cipher {alg}")
        for m in code_finditer(_RSA_SIZED_RE, text, scan_text):
            bits = int(m.group(1))
            cls = Classification.SANGAT_TINGGI if bits < 3072 else Classification.TINGGI
            sev = Severity.CRIT if bits < 3072 else Severity.HIGH
            _emit(f"RSA-{bits}", cls, sev, m, f"RSA-{bits} key generation")
        for m in code_finditer(_RSA_BARE_RE, text, scan_text):
            # No explicit size → .NET defaults to a 2048-bit key, which is
            # below the CNSA 3072-bit floor, so it classifies as SANGAT_TINGGI
            # exactly like the sized path above.
            _emit("RSA-2048", Classification.SANGAT_TINGGI, Severity.CRIT, m,
                  "RSA key generation (default 2048)")
        for m in code_finditer(_DSA_RE, text, scan_text):
            _emit("DSA", Classification.SANGAT_TINGGI, Severity.CRIT, m, "DSA key generation")
        for m in code_finditer(_EC_RE, text, scan_text):
            raw = _group(m)
            alg = "ECDSA" if raw.startswith("ECDSA") else "ECDH"
            _emit(alg, Classification.TINGGI, Severity.HIGH, m,
                  f"{alg} key agreement/signature (Shor-broken)")
        for m in code_finditer(_ECB_RE, text, scan_text):
            _emit("AES-ECB", Classification.SANGAT_TINGGI, Severity.CRIT, m,
                  "ECB cipher mode")
        for m in code_finditer(_CBC_RE, text, scan_text):
            _emit("AES-CBC", Classification.TINGGI, Severity.HIGH, m,
                  "CBC cipher mode (padding-oracle risk)")
