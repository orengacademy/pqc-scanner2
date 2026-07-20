"""Weighted migration-readiness score — CryptoScan's four-weight posture model.

This is a *companion* to (not a replacement for) two existing scores:

* :func:`pqcscan.core.bands.readiness_score` — a band-count average (green=100,
  yellow=50, red=0) over the traffic-light classification, and
* :mod:`pqcscan.core.mosca` — the orthogonal time-horizon (X+Y>Z) view.

Where ``readiness_score`` buckets each asset into three coarse bands, this module
grades every *cryptographic* finding on a finer four-weight scale that reflects
how much migration work remains for that asset:

===============  ======  ==================================================
Weight           %       Meaning
===============  ======  ==================================================
quantum-safe     100     Pure PQC already deployed (PQC_READY, no hybrid name)
hybrid           80      Composite / hybrid PQC (classical + PQC together)
partial          30      Weakened-but-not-quantum-broken (AES-128 class)
vulnerable       0       Classically-broken by Shor (RSA/ECC class)
===============  ======  ==================================================

The score is the weighted average expressed as a 0-100 percentage:

    score = (safe*100 + hybrid*80 + partial*30) / (total*100) * 100

where ``total`` is the number of crypto findings (INFO/ERROR rows are skipped —
they are not crypto assets). When there are **no** crypto findings at all the
score is defined as ``100.0`` / ``EXCELLENT``: nothing was found vulnerable, so
there is nothing to migrate. Pure stdlib and deterministic — never reads the
wall clock; identical inputs always yield an identical score.
"""
from __future__ import annotations

from dataclasses import dataclass

# Algorithm-name fragments identifying PQC primitives (lowercased substring
# match). Kept local so this module does not depend on bands.py.
_PQC_FRAGMENTS: tuple[str, ...] = (
    "ml-kem", "mlkem", "ml-dsa", "mldsa", "slh-dsa", "slhdsa", "fn-dsa",
    "kyber", "dilithium", "falcon", "sphincs",
)

# Classical-name fragments; a name carrying *both* a PQC and a classical
# fragment (or an explicit "+") is a composite / hybrid deployment.
_CLASSICAL_FRAGMENTS: tuple[str, ...] = (
    "ecdsa", "ecdh", "ed25519", "ed448", "rsa",
    "x25519", "x448", "p-256", "p256", "p-384", "p384", "p-521", "p521",
    "secp256", "secp384", "secp521", "brainpool", "nistp",
)

# Band thresholds on the 0-100 score.
_EXCELLENT, _GOOD, _MODERATE, _POOR = 90.0, 70.0, 50.0, 25.0


@dataclass(frozen=True)
class MigrationReadiness:
    """Weighted migration-readiness posture over a scan's crypto findings."""

    total: int          # crypto findings graded (safe+hybrid+partial+vulnerable)
    safe: int           # PQC_READY, pure PQC -> 100%
    hybrid: int         # composite/hybrid names ("+" or PQC+classical) -> 80%
    partial: int        # SEDERHANA/RENDAH, weak-but-not-quantum-broken -> 30%
    vulnerable: int     # SANGAT_TINGGI/TINGGI, classically broken -> 0%
    score: float        # 0..100 weighted percentage
    band: str           # EXCELLENT/GOOD/MODERATE/POOR/CRITICAL


def _classification_value(finding: object) -> str:
    classif = getattr(finding, "classification", "")
    return classif.value if hasattr(classif, "value") else str(classif)


def _is_hybrid(algorithm: str) -> bool:
    """True when ``algorithm`` names a composite/hybrid (classical + PQC) scheme.

    Recognises the explicit ``+`` join (e.g. ``X25519+ML-KEM-768``) and the
    concatenated NIST composite/hybrid names that carry both a PQC and a
    classical token without a separator (e.g. ``X25519MLKEM768``,
    ``MLDSA65-ECDSA-P256``).
    """
    a = algorithm.lower()
    if "+" in a:
        return True
    has_pqc = any(frag in a for frag in _PQC_FRAGMENTS)
    has_classical = any(frag in a for frag in _CLASSICAL_FRAGMENTS)
    return has_pqc and has_classical


def _band_for(score: float) -> str:
    if score >= _EXCELLENT:
        return "EXCELLENT"
    if score >= _GOOD:
        return "GOOD"
    if score >= _MODERATE:
        return "MODERATE"
    if score >= _POOR:
        return "POOR"
    return "CRITICAL"


def score_findings(findings: list) -> MigrationReadiness:
    """Grade ``findings`` into the four weights and return a MigrationReadiness.

    INFO / ERROR findings are skipped (not crypto assets). Each remaining
    finding is classified by its ``classification`` — except that any finding
    whose ``algorithm`` names a hybrid/composite scheme counts as *hybrid* (80%)
    regardless of classification, since a hybrid deployment is not yet fully
    quantum-safe. An empty set scores 100.0 / EXCELLENT (nothing to migrate).
    """
    safe = hybrid = partial = vulnerable = 0
    for f in findings:
        classif = _classification_value(f)
        if classif in ("info", "error"):
            continue
        if _is_hybrid(getattr(f, "algorithm", "") or ""):
            hybrid += 1
        elif classif == "pqc-ready":
            safe += 1
        elif classif in ("sederhana", "rendah"):
            partial += 1
        elif classif in ("sangat-tinggi", "tinggi"):
            vulnerable += 1
        # Any other value is not a gradable crypto asset; ignore it.

    total = safe + hybrid + partial + vulnerable
    if total == 0:
        return MigrationReadiness(0, 0, 0, 0, 0, 100.0, "EXCELLENT")

    weighted = safe * 100 + hybrid * 80 + partial * 30
    score = weighted / (total * 100) * 100
    score = round(score, 1)
    return MigrationReadiness(
        total=total,
        safe=safe,
        hybrid=hybrid,
        partial=partial,
        vulnerable=vulnerable,
        score=score,
        band=_band_for(score),
    )
