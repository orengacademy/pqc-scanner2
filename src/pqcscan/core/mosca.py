"""Mosca's inequality — the CISO-facing "does my data outlive my crypto?" test.

Mosca's theorem says a system is exposed to a future cryptographically-relevant
quantum computer (CRQC) when::

    X + Y > Z

where

* **X** — how many years the data must stay secret (data-lifetime),
* **Y** — how many years it takes to migrate to post-quantum crypto,
* **Z** — how many years until a CRQC exists (the quantum threat horizon).

When ``X + Y > Z`` any data harvested today is still secret-worthy at the moment
a CRQC can break the classical crypto protecting it *and* migration has not yet
finished — so it is at risk. The shortfall ``(X + Y) - Z`` is the "shelf-life
gap" in years: how far the migration overruns the safe window.

This module is a companion to :func:`pqcscan.core.bands.readiness_score` (a
0-100 posture score); it adds the orthogonal *time-horizon* view. Pure stdlib,
deterministic arithmetic on the inputs only — it never reads the wall clock.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class MoscaInputs:
    """The three time horizons that drive Mosca's inequality, all in years."""

    data_lifetime_years: float          # X — how long the data must stay secret
    migration_years: float = 5.0        # Y — time to migrate to PQC
    threat_years: float = 10.0          # Z — years until a CRQC exists


@dataclass(frozen=True)
class MoscaResult:
    """Outcome of evaluating :class:`MoscaInputs` against Mosca's inequality."""

    x: float
    y: float
    z: float
    sum_xy: float                       # X + Y
    gap_years: float                    # (X + Y) - Z ; positive ⇒ at risk
    at_risk: bool                       # gap_years > 0
    verdict: str                        # "at-risk" | "ok"

    def as_dict(self) -> dict[str, Any]:
        """Return a plain-dict view for the report context / JSON export."""
        return asdict(self)


def assess(inputs: MoscaInputs) -> MoscaResult:
    """Evaluate Mosca's inequality for ``inputs`` and return a MoscaResult.

    ``at_risk`` is true only when ``X + Y`` strictly exceeds ``Z``; the boundary
    case ``X + Y == Z`` (gap 0) is treated as *not* at risk — migration finishes
    exactly as the threat arrives.
    """
    x = float(inputs.data_lifetime_years)
    y = float(inputs.migration_years)
    z = float(inputs.threat_years)
    sum_xy = x + y
    gap = sum_xy - z
    at_risk = gap > 0.0
    return MoscaResult(
        x=x,
        y=y,
        z=z,
        sum_xy=sum_xy,
        gap_years=gap,
        at_risk=at_risk,
        verdict="at-risk" if at_risk else "ok",
    )


def _fmt(n: float) -> str:
    """Render a year count without a trailing ``.0`` (e.g. ``5.0`` → ``5``)."""
    return str(int(n)) if float(n).is_integer() else f"{n:g}"


def summary_lines(result: MoscaResult, vulnerable_count: int = 0) -> dict[str, str]:
    """Return a short human summary of ``result`` as ``{"en": ..., "ms": ...}``.

    ``vulnerable_count`` is the number of quantum-vulnerable findings from the
    scan; it colours the at-risk sentence but is optional. Deterministic — the
    same inputs always yield the same strings.
    """
    x, y, z = _fmt(result.x), _fmt(result.y), _fmt(result.z)
    total = _fmt(result.sum_xy)
    gap = _fmt(abs(result.gap_years))

    if result.at_risk:
        en = (
            f"At risk: data must stay secret for {x} year(s) and migration takes "
            f"{y} year(s) ({total} in total), but a quantum computer is expected "
            f"in {z} year(s) — a shelf-life gap of {gap} year(s). "
            f"{vulnerable_count} quantum-vulnerable asset(s) are exposed to "
            f"harvest-now-decrypt-later."
        )
        ms = (
            f"Berisiko: data perlu dirahsiakan selama {x} tahun dan migrasi "
            f"mengambil masa {y} tahun ({total} tahun kesemuanya), tetapi komputer "
            f"kuantum dijangka dalam {z} tahun — jurang jangka-hayat {gap} tahun. "
            f"{vulnerable_count} aset terdedah-kuantum terdedah kepada "
            f"tuai-kini-nyahsulit-kemudian."
        )
    else:
        en = (
            f"Within safe window: data-lifetime plus migration ({total} year(s)) "
            f"does not exceed the {z}-year quantum horizon (margin {gap} year(s))."
        )
        ms = (
            f"Dalam tempoh selamat: jangka-hayat data campur migrasi ({total} "
            f"tahun) tidak melebihi ufuk kuantum {z} tahun (margin {gap} tahun)."
        )
    return {"en": en, "ms": ms}
