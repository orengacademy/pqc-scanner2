"""code.crypto_primitives — cross-language source-code crypto primitive scanner.

A single, broad probe that complements the narrow per-language ``code.ts.*``
probes. Instead of one regex set per language, it walks every supported source
suffix and matches a wide, reviewable corpus of crypto *primitives* — named
curves, RSA padding schemes, AEAD/block-cipher modes, bare hash names, key-gen
sizes, and (positively) PQC library/algorithm references.

Design constraints:
  - No tree-sitter: it ships platform-specific compiled grammars, which would
    break the self-contained any-OS binary. This stays pure-regex, zero deps.
  - The primitive corpus lives in ``PRIMITIVE_PATTERNS`` as a flat, structured
    ``(regex, algorithm, classification)`` list so a new entry is a one-line,
    reviewable, testable diff. Regexes compile once at import time.

Findings de-dup on ``(file, algorithm)`` so a file that mentions the same
primitive many times yields a single finding.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._code_walker import walk_source
from pqcscan.probes._severity import sev_for

# Source suffixes scanned across every language. Kept broad on purpose — the
# corpus below is language-agnostic (it matches crypto vocabulary, not syntax).
_SUFFIXES: tuple[str, ...] = (
    ".py", ".js", ".ts", ".go", ".rs", ".java",
    ".rb", ".php", ".c", ".cpp", ".cs", ".kt", ".swift",
)

_T = Classification.TINGGI
_ST = Classification.SANGAT_TINGGI
_SD = Classification.SEDERHANA
_RN = Classification.RENDAH
_PQC = Classification.PQC_READY

# --- primitive corpus ----------------------------------------------------
# (compiled-regex, canonical-algorithm, classification). Aliases for the same
# primitive are grouped into one alternation so they collapse to one finding.
# All patterns are case-insensitive; keep additions here so the list stays the
# single reviewable source of truth.
_RAW_PATTERNS: tuple[tuple[str, str, Classification], ...] = (
    # --- Named elliptic curves (ECDSA/ECDH — Shor-broken) → TINGGI ---
    (r"secp256r1|prime256v1|\bP-256\b|NIST\s*P-256", "P-256 (secp256r1)", _T),
    (r"secp384r1|\bP-384\b|NIST\s*P-384", "P-384 (secp384r1)", _T),
    (r"secp521r1|\bP-521\b|NIST\s*P-521", "P-521 (secp521r1)", _T),
    (r"secp256k1", "secp256k1", _T),
    (r"brainpoolP[0-9]+[rt][0-9]", "brainpool", _T),
    # --- Curve25519 / Edwards family → TINGGI ---
    (r"\bEd25519\b", "Ed25519", _T),
    (r"\bX25519\b", "X25519", _T),
    (r"\bcurve25519\b", "Curve25519", _T),
    (r"\bed448\b", "Ed448", _T),
    (r"\bx448\b", "X448", _T),
    # --- RSA padding schemes ---
    (r"PKCS1_?v1_?5|PKCS1v15|PKCS1_v1_5|PKCS1Padding", "RSA-PKCS1v15", _ST),
    (r"\bOAEP\b", "RSA-OAEP", _T),
    (r"\bPSS\b|RSASSA-?PSS", "RSA-PSS", _T),
    # --- AEAD / block-cipher modes ---
    (r"AES[-_ ]?256[-_ ]?GCM", "AES-256-GCM", _RN),
    (r"AES.{0,8}GCM|AES[-_ ]?GCM|MODE_GCM|GCMParameterSpec", "AES-GCM", _SD),
    (r"AES.{0,10}CBC|MODE_CBC|AES[-_ ]?CBC", "AES-CBC", _T),
    (r"AES.{0,10}ECB|MODE_ECB|AES[-_ ]?ECB|\bECB\b", "AES-ECB", _ST),
    (r"\bChaCha20\b", "ChaCha20", _RN),
    (r"\b3DES\b|DESede|TripleDES|\bDES3\b|TDES", "3DES", _ST),
    (r"\bRC4\b|ARCFOUR|ARC4", "RC4", _ST),
    (r"\bBlowfish\b", "Blowfish", _T),
    # --- Bare hash names in code ---
    (r"\bMD5\b", "MD5", _ST),
    (r"\bSHA-?1\b|\bSHA1\b", "SHA-1", _ST),
    (r"\bSHA-?256\b|\bSHA256\b", "SHA-256", _SD),
    # --- PQC library / algorithm references (positive signal) → PQC_READY ---
    (r"ML[-_ ]?KEM|\bMLKEM\b|\bKyber", "ML-KEM", _PQC),
    (r"ML[-_ ]?DSA|\bMLDSA\b|\bDilithium", "ML-DSA", _PQC),
    (r"SLH[-_ ]?DSA|\bSPHINCS", "SLH-DSA", _PQC),
    (r"\bFalcon\b", "Falcon", _PQC),
    (r"\bliboqs\b|\bpqcrypto\b|\boqs\.", "liboqs/pqcrypto", _PQC),
    # --- RSA key-gen sizes ---
    (
        r"RSA.{0,20}(?:1024|2048)|generate_private_key[\s\S]{0,60}?(?:1024|2048)"
        r"|key_size\s*=\s*(?:1024|2048)|\.generate\s*\(\s*(?:1024|2048)",
        "RSA-2048",
        _ST,
    ),
    (
        r"RSA.{0,20}(?:3072|4096)|key_size\s*=\s*(?:3072|4096)"
        r"|\.generate\s*\(\s*(?:3072|4096)",
        "RSA-3072/4096",
        _T,
    ),
)

# Compiled once at import time.
PRIMITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str, Classification], ...] = tuple(
    (re.compile(pat, re.IGNORECASE), alg, cls) for pat, alg, cls in _RAW_PATTERNS
)


class CodeCryptoPrimitives(Probe):
    """Broad cross-language crypto-primitive scanner (complements code.ts.*)."""

    id = "code.crypto_primitives"
    family = ProbeFamily.CODE
    framework_tags = ("nist-ir-8547:code", "mykripto:code")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        roots = self.roots if self.roots is not None else ctx.scan_paths
        for path in walk_source(roots, _SUFFIXES):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        lines = text.splitlines()
        seen: set[str] = set()  # de-dup (file, algorithm) — file is fixed here
        for pattern, algorithm, classification in PRIMITIVE_PATTERNS:
            m = pattern.search(text)
            if m is None or algorithm in seen:
                continue
            seen.add(algorithm)
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip()[:160] if 0 < line_no <= len(lines) else ""
            emit(Finding(
                probe_id=self.id,
                algorithm=algorithm,
                classification=classification,
                severity=sev_for(classification),
                title=f"{algorithm} primitive in {path}:{line_no}",
                evidence={
                    "file": str(path),
                    "line": line_no,
                    "primitive": algorithm,
                    "snippet": snippet,
                },
                remediation={
                    "snippet": "# Migrate to FIPS 203/204/205 (ML-KEM/ML-DSA/SLH-DSA) "
                               "or AES-256-GCM as appropriate",
                },
            ))
