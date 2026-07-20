"""Tests for the ``pqcscan scan --fail-on`` CI gate.

The gate logic is factored into the pure helpers ``_findings_at_or_over`` /
``_gate_tripped`` so the severity-threshold comparison can be exercised fast and
deterministically without driving a full local scan.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from pqcscan.cli.scan import (
    FAIL_ON_CHOICES,
    _findings_at_or_over,
    _gate_tripped,
    _threshold_numeric,
    scan_cmd,
)


def _f(severity: str) -> SimpleNamespace:
    """A minimal stand-in for a stored finding (severity is a plain str)."""
    return SimpleNamespace(severity=severity)


def test_choices_ordered_least_to_most_severe() -> None:
    assert FAIL_ON_CHOICES == ("none", "low", "med", "high", "crit")


def test_threshold_numeric_none_disables_gate() -> None:
    assert _threshold_numeric("none") is None
    assert _threshold_numeric("high") == 3
    assert _threshold_numeric("crit") == 4


def test_default_high_gate_trips_on_crit() -> None:
    # Default (--fail-on omitted == "high") with a crit finding -> exit 1.
    assert _gate_tripped([_f("crit")], "high") is True


def test_fail_on_none_never_trips_even_with_crit() -> None:
    # --fail-on none with a crit finding -> exit 0.
    assert _gate_tripped([_f("crit")], "none") is False


def test_fail_on_crit_passes_on_high_only() -> None:
    # --fail-on crit with only a high finding -> exit 0.
    assert _gate_tripped([_f("high")], "crit") is False


def test_fail_on_low_trips_on_low() -> None:
    # --fail-on low with a low finding -> exit 1.
    assert _gate_tripped([_f("low")], "low") is True


def test_at_or_over_is_inclusive_and_counts() -> None:
    findings = [_f("info"), _f("low"), _f("med"), _f("high"), _f("crit")]
    assert len(_findings_at_or_over(findings, "med")) == 3
    assert len(_findings_at_or_over(findings, "crit")) == 1
    assert _findings_at_or_over(findings, "none") == []


@pytest.mark.parametrize(
    ("threshold", "severity", "expected"),
    [
        ("high", "crit", True),
        ("high", "med", False),
        ("none", "crit", False),
        ("crit", "high", False),
        ("low", "low", True),
        ("info", "info", True),
    ],
)
def test_gate_matrix(threshold: str, severity: str, expected: bool) -> None:
    assert _gate_tripped([_f(severity)], threshold) is expected


def test_option_registered_with_high_default() -> None:
    help_text = CliRunner().invoke(scan_cmd, ["--help"]).output
    collapsed = " ".join(help_text.split())
    assert "--fail-on" in collapsed
    assert "[none|low|med|high|crit]" in collapsed
    assert "default: high" in collapsed
