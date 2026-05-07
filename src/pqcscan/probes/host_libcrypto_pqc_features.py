"""host.libcrypto_pqc_features — inspect libcrypto/libssl exported symbols (Plan I.7.d).

OpenSSL 3.5 ships native ML-KEM / ML-DSA / SLH-DSA support; older versions
need oqs-provider. This probe shells out `nm -D` against common libssl
locations and greps for FIPS 203/204/205 markers in the exported symbol table.

INFO-skip if `nm` not on PATH (typical on minimal containers / Windows).
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_LIBSSL_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    "/usr/lib64/libssl.so.3",
    "/usr/lib64/libcrypto.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/local/lib/libssl.so.3",
    "/usr/local/lib/libcrypto.so.3",
    "/opt/homebrew/lib/libssl.3.dylib",
    "/opt/homebrew/lib/libcrypto.3.dylib",
    "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
)

_PQC_MARKERS = (
    "ML_KEM", "ML-KEM", "ml_kem",
    "ML_DSA", "ml_dsa",
    "SLH_DSA", "slh_dsa",
    "EVP_PKEY_kem",
    "Kyber", "Dilithium", "SPHINCS",
)


class HostLibcryptoPqcFeatures(Probe):
    id = "host.libcrypto_pqc_features"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:tls", "cnsa2:tls", "nacsa-9:pqc-readiness")

    async def applies(self, ctx: ScanContext) -> bool:
        return shutil.which("nm") is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        existing = [Path(p) for p in _LIBSSL_CANDIDATES if Path(p).exists()]
        if not existing:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title="no libssl/libcrypto found in default locations",
                evidence={"candidates": list(_LIBSSL_CANDIDATES)},
            ))
            return

        for lib in existing:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nm", "-D", "--defined-only", str(lib),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            except (TimeoutError, OSError) as e:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.INFO,
                    title=f"nm -D failed on {lib}",
                    evidence={"lib": str(lib), "error": repr(e)},
                ))
                continue

            text = stdout_b.decode("utf-8", errors="replace")
            hits = [m for m in _PQC_MARKERS if m in text]
            if hits:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="libssl-pqc",
                    classification=Classification.PQC_READY,
                    severity=Severity.INFO,
                    title=f"libssl PQC symbols found in {lib}",
                    evidence={
                        "lib": str(lib),
                        "markers_matched": sorted(set(hits)),
                        "marker_count": len(hits),
                    },
                ))
            else:
                emit(Finding(
                    probe_id=self.id,
                    algorithm="N/A",
                    classification=Classification.INFO,
                    severity=Severity.LOW,
                    title=f"libssl at {lib} lacks native PQC symbols",
                    evidence={
                        "lib": str(lib),
                        "remediation": (
                            "Upgrade to OpenSSL 3.5+ for native ML-KEM, or "
                            "load oqs-provider into 3.0-3.4."
                        ),
                    },
                ))
