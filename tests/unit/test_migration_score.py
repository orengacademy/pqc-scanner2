"""Weighted migration-readiness score (core.migration_score)."""
from __future__ import annotations

from pqcscan.core.migration_score import MigrationReadiness, score_findings
from pqcscan.core.types import Classification, Finding, Severity


def _f(classification: Classification, algorithm: str = "N/A", severity: Severity = Severity.MED) -> Finding:
    return Finding(
        probe_id="x.y",
        algorithm=algorithm,
        classification=classification,
        severity=severity,
        title="t",
    )


def test_empty_is_excellent() -> None:
    r = score_findings([])
    assert isinstance(r, MigrationReadiness)
    assert r.total == 0
    assert r.score == 100.0
    assert r.band == "EXCELLENT"


def test_all_safe_is_100_excellent() -> None:
    r = score_findings([_f(Classification.PQC_READY, "ML-KEM-768") for _ in range(3)])
    assert (r.safe, r.total) == (3, 3)
    assert r.score == 100.0
    assert r.band == "EXCELLENT"


def test_all_vulnerable_is_0_critical() -> None:
    r = score_findings([_f(Classification.SANGAT_TINGGI, "RSA-2048") for _ in range(4)])
    assert (r.vulnerable, r.total) == (4, 4)
    assert r.score == 0.0
    assert r.band == "CRITICAL"


def test_mix_weighted_number_and_band() -> None:
    # 1 safe (100) + 1 hybrid (80) + 2 vulnerable (0) over 4*100 -> 45.0 -> POOR.
    findings = [
        _f(Classification.PQC_READY, "ML-DSA-65"),
        _f(Classification.PQC_READY, "X25519MLKEM768"),   # hybrid name overrides -> 80%
        _f(Classification.SANGAT_TINGGI, "RSA-2048"),
        _f(Classification.TINGGI, "ECDSA-P256"),
    ]
    r = score_findings(findings)
    assert (r.safe, r.hybrid, r.vulnerable, r.total) == (1, 1, 2, 4)
    assert r.score == 45.0
    assert r.band == "POOR"


def test_partial_weight_is_30() -> None:
    # 1 partial (AES-128 weakened) alone -> 30.0 -> MODERATE boundary is 50, so POOR.
    r = score_findings([_f(Classification.SEDERHANA, "AES-128")])
    assert (r.partial, r.total) == (1, 1)
    assert r.score == 30.0
    assert r.band == "POOR"


def test_info_and_error_are_ignored() -> None:
    findings = [
        _f(Classification.PQC_READY, "ML-KEM-768"),
        _f(Classification.INFO, "N/A"),
        _f(Classification.ERROR, "N/A"),
    ]
    r = score_findings(findings)
    assert r.total == 1        # only the PQC-ready crypto asset is graded
    assert r.score == 100.0


def test_explicit_plus_hybrid_name() -> None:
    r = score_findings([_f(Classification.SANGAT_TINGGI, "X25519+ML-KEM-768")])
    # Hybrid name overrides the classification -> counts as hybrid, not vulnerable.
    assert (r.hybrid, r.vulnerable) == (1, 0)
    assert r.score == 80.0
    assert r.band == "GOOD"
