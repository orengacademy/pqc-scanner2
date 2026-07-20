"""Multi-axis exposure register — per-asset quantum-migration prioritisation.

Mosca's inequality (:mod:`pqcscan.core.mosca`) answers "does my data outlive my
crypto?" at the *portfolio* level. This module *operationalises* that same
"data must stay secret long enough to matter" intuition down to the individual
asset, so an operator gets an ordered worklist instead of one aggregate verdict.

Each quantum-vulnerable finding is scored on three independent 1-3 axes,
multiplied into an exposure figure (1..27), then bucketed into a tier. Every
axis is derived deterministically from data already on the Finding — we do NOT
invent business context (asset owner, data value) we do not have:

criticality (from ``severity``)
    crit → 3, high → 2, everything else → 1.

longevity (from ``probe_id`` family — how long the protected secret lives)
    Long-lived key material — certificates, keystores, KMS, signing keys,
    at-rest DB crypto (``fs.cert*`` / ``fs.keystore*`` / ``*.kms`` /
    ``fs.db*`` / ``secrets.*`` / ``sign.*``) → 3.
    Transport / config crypto (``net.*`` / ``fs.conf*`` / ``vpn.*`` / any
    ``tls``) → 2. Everything else → 1.

feasibility (from ``probe_id`` family — how hard the fix is; higher = harder)
    A config flip (``fs.conf*`` / ``net.*`` / ``*config*``) → 1.
    Baked-in crypto — source/SBOM, DB-embedded, host binaries, containers,
    OT/firmware/appliance (``code.*`` / ``sbom.*`` / ``fs.db*`` / ``host.*`` /
    ``container.*`` / ``ot.*`` / firmware / appliance) → 3. Everything else → 2.

    exposure = criticality * longevity * feasibility        (1..27)
    tier     = CRITICAL >= 18 / HIGH >= 9 / MEDIUM >= 4 / LOW < 4

The register lists only quantum-vulnerable findings (SANGAT_TINGGI / TINGGI);
PQC-ready, hybrid, informational and weakened-only (SEDERHANA/RENDAH) rows are
excluded. It is sorted by exposure descending (ties broken deterministically by
finding reference) and capped at the top 200. Pure stdlib, no wall clock.
"""
from __future__ import annotations

from dataclasses import dataclass

from pqcscan.core.migration_score import _is_hybrid

_MAX_ROWS = 200

# Tier thresholds on the 1..27 exposure product.
_CRITICAL, _HIGH, _MEDIUM = 18, 9, 4

# probe_id prefixes / fragments driving the longevity axis (long-lived secrets).
_LONGEVITY_HIGH_PREFIXES = ("fs.cert", "fs.keystore", "fs.db", "secrets.", "sign.")
_LONGEVITY_MID_PREFIXES = ("net.", "fs.conf", "vpn.")

# probe_id prefixes / fragments driving the feasibility axis.
_FEASIBILITY_EASY_PREFIXES = ("fs.conf", "net.")
_FEASIBILITY_HARD_PREFIXES = ("code.", "sbom.", "fs.db", "host.", "container.", "ot.")
_FEASIBILITY_HARD_FRAGMENTS = ("binary", "appliance", "firmware")

# Evidence keys probed (in order) for a short human locator.
_LOCATOR_KEYS = ("endpoint", "host", "target", "path", "file", "location")


@dataclass(frozen=True)
class ExposureRow:
    """One quantum-vulnerable asset scored across the three exposure axes."""

    finding_ref: str    # probe_id + short locator from evidence
    algorithm: str
    criticality: int    # 1-3 from severity
    longevity: int      # 1-3 from probe family (secret lifetime)
    feasibility: int    # 1-3 from probe family (migration difficulty)
    exposure: int       # criticality * longevity * feasibility (1..27)
    tier: str           # CRITICAL / HIGH / MEDIUM / LOW


def _classification_value(finding: object) -> str:
    classif = getattr(finding, "classification", "")
    return classif.value if hasattr(classif, "value") else str(classif)


def _severity_value(finding: object) -> str:
    sev = getattr(finding, "severity", "")
    return sev.value if hasattr(sev, "value") else str(sev)


def _is_vulnerable(finding: object) -> bool:
    """True for classically-broken (quantum-vulnerable) crypto findings only.

    Hybrid/composite deployments are excluded — a hybrid already carries a PQC
    component, so it is not a migration blocker in this register.
    """
    if _is_hybrid(getattr(finding, "algorithm", "") or ""):
        return False
    return _classification_value(finding) in ("sangat-tinggi", "tinggi")


def _criticality(finding: object) -> int:
    sev = _severity_value(finding)
    if sev == "crit":
        return 3
    if sev == "high":
        return 2
    return 1


def _longevity(pid: str) -> int:
    if pid.startswith(_LONGEVITY_HIGH_PREFIXES) or ".kms" in pid:
        return 3
    if pid.startswith(_LONGEVITY_MID_PREFIXES) or "tls" in pid:
        return 2
    return 1


def _feasibility(pid: str) -> int:
    if pid.startswith(_FEASIBILITY_EASY_PREFIXES) or "config" in pid:
        return 1
    if pid.startswith(_FEASIBILITY_HARD_PREFIXES) or any(
        frag in pid for frag in _FEASIBILITY_HARD_FRAGMENTS
    ):
        return 3
    return 2


def _tier(exposure: int) -> str:
    if exposure >= _CRITICAL:
        return "CRITICAL"
    if exposure >= _HIGH:
        return "HIGH"
    if exposure >= _MEDIUM:
        return "MEDIUM"
    return "LOW"


def _locator(finding: object) -> str:
    evidence = getattr(finding, "evidence", None) or {}
    for key in _LOCATOR_KEYS:
        val = evidence.get(key)
        if val:
            text = str(val)
            if key == "host" and evidence.get("port"):
                text = f"{text}:{evidence['port']}"
            return text[:60]
    return ""


def _row_for(finding: object) -> ExposureRow:
    pid = (getattr(finding, "probe_id", "") or "").lower()
    algorithm = getattr(finding, "algorithm", "") or ""
    criticality = _criticality(finding)
    longevity = _longevity(pid)
    feasibility = _feasibility(pid)
    exposure = criticality * longevity * feasibility
    loc = _locator(finding)
    ref = f"{getattr(finding, 'probe_id', '')}@{loc}" if loc else (getattr(finding, "probe_id", "") or "")
    return ExposureRow(
        finding_ref=ref,
        algorithm=algorithm,
        criticality=criticality,
        longevity=longevity,
        feasibility=feasibility,
        exposure=exposure,
        tier=_tier(exposure),
    )


def build_register(findings: list) -> list[ExposureRow]:
    """Return quantum-vulnerable findings as ExposureRows, worst-exposure first.

    Sorted by exposure descending, ties broken by ``finding_ref`` then
    ``algorithm`` for determinism, and capped at the top :data:`_MAX_ROWS`.
    """
    rows = [_row_for(f) for f in findings if _is_vulnerable(f)]
    rows.sort(key=lambda r: (-r.exposure, r.finding_ref, r.algorithm))
    return rows[:_MAX_ROWS]


def tier_counts(rows: list[ExposureRow]) -> dict[str, int]:
    """Return a ``{tier: count}`` summary over ``rows`` (all four tiers keyed)."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in rows:
        counts[r.tier] += 1
    return counts
