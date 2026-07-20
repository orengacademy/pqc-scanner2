"""CI regression gate for probe accuracy.

Runs the labelled benchmark corpus and locks in the precision guarantee the
comment/string-suppression + AST work provides: every negative must NOT fire,
so overall precision is exactly 1.0 (zero false positives). Recall is gated a
touch below the measured value to allow one future hard miss without a red build
while still catching a real recall regression.

Also guards the corpus against rot: every manifest input path must exist and
every probe id must resolve in the registry.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "benchmark"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

import run_benchmark as rb  # noqa: E402

# Measured on the seeded corpus: precision 1.000, recall 1.000. The precision
# bar is the whole point — never lower it below the measured value. Recall is
# set one hard-miss below 1.0 as headroom.
MIN_PRECISION = 1.0
MIN_RECALL = 0.95


@pytest.fixture(scope="module")
def report() -> rb.Report:
    cases = rb.load_manifest()
    return rb.evaluate(cases)


def test_manifest_inputs_exist() -> None:
    for case in rb.load_manifest():
        input_path = (rb.CORPUS_DIR / case["input"]).resolve()
        assert input_path.exists(), f"case {case['id']} input missing: {input_path}"


def test_manifest_probe_ids_resolve() -> None:
    registry = rb.default_registry()
    known = set(registry.ids())
    for case in rb.load_manifest():
        assert case["probe"] in known, f"case {case['id']} unknown probe: {case['probe']}"


def test_corpus_has_both_polarities() -> None:
    cases = rb.load_manifest()
    kinds = {c["kind"] for c in cases}
    assert kinds == {"positive", "negative"}, kinds
    assert len(cases) >= 40, f"corpus too small: {len(cases)} cases"


def test_precision_is_perfect(report: rb.Report) -> None:
    # Zero false positives across every negative case — the precision guarantee.
    assert report.fp == 0, [c for c in report.cases if c.outcome == "FP"]
    assert report.precision == MIN_PRECISION, report.precision


def test_recall_above_floor(report: rb.Report) -> None:
    assert report.recall is not None
    assert report.recall >= MIN_RECALL, (
        report.recall,
        [c for c in report.cases if c.outcome == "FN"],
    )
