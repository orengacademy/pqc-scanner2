"""app.crypto_lib_pqc_support — scan project deps for PQC crypto libraries (Plan I.7.d).

Walks ctx.scan_paths for dependency manifests (requirements.txt, Pipfile,
pyproject.toml, package.json, Cargo.toml, pom.xml, build.gradle, composer.json,
go.mod) and emits a Finding for each known PQC crypto library reference.
"""
from __future__ import annotations

import re

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_PQC_LIB_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("liboqs",             re.compile(r"\b(?:liboqs|oqs-python|pyoqs)\b", re.I), "liboqs-python"),
    ("bouncycastle-pqc",   re.compile(r"\bbc(?:prov-|pqc|-pqc)[a-z0-9._-]*\b", re.I), "BouncyCastle PQC"),
    ("pqcrypto-rs",        re.compile(r"\bpqcrypto(?:-[a-z]+)?\b", re.I), "pqcrypto Rust crate"),
    ("pqclean",            re.compile(r"\bpqclean\b", re.I), "PQClean"),
    ("kyber-py",           re.compile(r"\bkyber[-_]?py\b", re.I), "kyber-py"),
    ("dilithium-py",       re.compile(r"\bdilithium[-_]?py\b", re.I), "dilithium-py"),
    ("mlkem-py",           re.compile(r"\bml[-_]?kem(?:[-_]?py)?\b", re.I), "ML-KEM Python lib"),
    ("noble/post-quantum", re.compile(r"@noble/post-quantum|post-quantum", re.I), "@noble/post-quantum"),
    ("circl",              re.compile(r"\bcloudflare/circl\b", re.I), "Cloudflare CIRCL (Go)"),
)

_DEP_FILES = (
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
    "package.json", "package-lock.json", "yarn.lock",
    "Cargo.toml", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "composer.json", "composer.lock",
    "go.mod", "go.sum",
)


class AppCryptoLibPqcSupport(Probe):
    id = "app.crypto_lib_pqc_support"
    family = ProbeFamily.APP
    framework_tags = ("nist-ir-8547:app", "cnsa2:app", "nacsa-9:pqc-readiness")

    async def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.scan_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[tuple[str, str]] = set()
        for root in ctx.scan_paths:
            if not root.is_dir():
                continue
            for fname in _DEP_FILES:
                for path in root.rglob(fname):
                    try:
                        text = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    for lib_id, pattern, label in _PQC_LIB_PATTERNS:
                        if not pattern.search(text):
                            continue
                        key = (lib_id, str(path))
                        if key in seen:
                            continue
                        seen.add(key)
                        emit(Finding(
                            probe_id=self.id,
                            algorithm=label,
                            classification=Classification.PQC_READY,
                            severity=Severity.INFO,
                            title=f"PQC lib {label} declared in {path}",
                            evidence={
                                "path": str(path),
                                "manifest": fname,
                                "library_id": lib_id,
                                "library_label": label,
                            },
                        ))
