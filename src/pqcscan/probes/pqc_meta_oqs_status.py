"""pqc.meta.oqs_status — reports liboqs-python availability + supported algos.

Plan I.7.a — meta probe that surfaces the OQS active-validation capability
state to scan reports. Always emits a Finding (PQC_READY when liboqs imports,
INFO otherwise). Provides downstream probes a single source of truth for
whether active hybrid-KEX / ML-DSA verify / KAT runs are possible.
"""
from __future__ import annotations

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._oqs_helper import (
    oqs_available,
    oqs_import_error,
    supported_kems,
    supported_sigs,
)


class PqcMetaOqsStatus(Probe):
    id = "pqc.meta.oqs_status"
    family = ProbeFamily.PQC_META
    framework_tags = ("nist-ir-8547:tls", "cnsa2:tls", "nacsa-9:pqc-readiness")

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        if oqs_available():
            kems = supported_kems()
            sigs = supported_sigs()
            ml_kem = [k for k in kems if "ML-KEM" in k or k.startswith("Kyber")]
            ml_dsa = [s for s in sigs if "ML-DSA" in s or s.startswith("Dilithium")]
            slh_dsa = [s for s in sigs if "SLH-DSA" in s or s.startswith("SPHINCS")]
            falcon = [s for s in sigs if s.startswith("Falcon")]
            emit(Finding(
                probe_id=self.id,
                algorithm="liboqs",
                classification=Classification.PQC_READY,
                severity=Severity.INFO,
                title=f"liboqs available — {len(kems)} KEMs + {len(sigs)} signatures",
                evidence={
                    "oqs_available": True,
                    "kem_count": len(kems),
                    "sig_count": len(sigs),
                    "ml_kem_variants": ml_kem,
                    "ml_dsa_variants": ml_dsa,
                    "slh_dsa_variants": slh_dsa,
                    "falcon_variants": falcon,
                },
            ))
        else:
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title="liboqs-python not available — active PQC validation disabled",
                evidence={
                    "oqs_available": False,
                    "import_error": oqs_import_error(),
                    "remediation": "pip install pqcscan[active] (requires native liboqs >= 0.10).",
                },
            ))
