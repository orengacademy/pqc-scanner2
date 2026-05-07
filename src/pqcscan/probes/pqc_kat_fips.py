"""pqc.kat.fips — NIST FIPS 203/204/205 KAT roundtrip runner (Plan I.7.e).

When liboqs-python (`pqcscan[active]` extras) is available, runs:
- FIPS 203 ML-KEM-512/768/1024  : keypair -> encap -> decap; verify shared
  secret matches.
- FIPS 204 ML-DSA-44/65/87       : keypair -> sign -> verify.
- FIPS 205 SLH-DSA-SHA2-128s/256s: keypair -> sign -> verify.

Each roundtrip is a self-test of the host's liboqs build. Pass = local
PQC primitives functional. Fail = liboqs build issue or mechanism not
enabled.

INFO-skip when liboqs not available (default install).
"""
from __future__ import annotations

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._oqs_helper import kem as _kem
from pqcscan.probes._oqs_helper import oqs_available
from pqcscan.probes._oqs_helper import signature as _signature

_KEM_VARIANTS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
_SIG_VARIANTS = (
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-256s",
)


def _run_kem_kat(name: str) -> tuple[bool, str]:
    try:
        with _kem(name) as alice:
            pub = alice.generate_keypair()
            with _kem(name) as bob:
                ct, ss_b = bob.encap_secret(pub)
                ss_a = alice.decap_secret(ct)
        ok = ss_a == ss_b and len(ss_a) > 0
        return ok, f"shared_secret_len={len(ss_a)}"
    except Exception as e:
        return False, f"error={e!r}"


def _run_sig_kat(name: str) -> tuple[bool, str]:
    try:
        msg = b"pqcscan KAT roundtrip"
        with _signature(name) as signer:
            pub = signer.generate_keypair()
            sig = signer.sign(msg)
        with _signature(name) as verifier:
            ok = verifier.verify(msg, sig, pub)
        return bool(ok), f"sig_len={len(sig)}"
    except Exception as e:
        return False, f"error={e!r}"


class PqcKatFips(Probe):
    id = "pqc.kat.fips"
    family = ProbeFamily.PQC_META
    framework_tags = (
        "nist-ir-8547:kat", "cnsa2:kat", "nacsa-9:pqc-readiness",
    )

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        if not oqs_available():
            emit(Finding(
                probe_id=self.id,
                algorithm="N/A",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title="liboqs-python not available — KAT roundtrips skipped",
                evidence={
                    "remediation": "pip install pqcscan[active] (requires native liboqs).",
                },
            ))
            return

        for name in _KEM_VARIANTS:
            ok, detail = _run_kem_kat(name)
            emit(Finding(
                probe_id=self.id,
                algorithm=name,
                classification=Classification.PQC_READY if ok else Classification.ERROR,
                severity=Severity.INFO if ok else Severity.HIGH,
                title=f"FIPS 203 KAT {name} {'PASS' if ok else 'FAIL'}",
                evidence={
                    "primitive_kind": "KEM",
                    "variant": name,
                    "result": detail,
                    "pass": ok,
                },
            ))

        for name in _SIG_VARIANTS:
            ok, detail = _run_sig_kat(name)
            spec = "FIPS 204" if name.startswith("ML-DSA") else "FIPS 205"
            emit(Finding(
                probe_id=self.id,
                algorithm=name,
                classification=Classification.PQC_READY if ok else Classification.ERROR,
                severity=Severity.INFO if ok else Severity.HIGH,
                title=f"{spec} KAT {name} {'PASS' if ok else 'FAIL'}",
                evidence={
                    "primitive_kind": "SIG",
                    "variant": name,
                    "result": detail,
                    "pass": ok,
                },
            ))
