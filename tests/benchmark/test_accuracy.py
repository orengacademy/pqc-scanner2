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


# Documented fail-open decisions (docs/ACCURACY.md, "Limits"): code.crypto_primitives
# does not strip comments/strings for C/C++, Ruby or Swift — no lexer is trusted for
# them, and a wrong one would let a crafted literal hide real code — so a mention
# there fires. These are the ONLY false positives the gate accepts; a fix that makes
# one pass must remove it here, and any other FP fails the build.
ACCEPTED_FP: dict[str, str] = {
    f"cp-{lang}-{form}-md5": "code.crypto_primitives: no trusted lexer for this language (fail-open)"
    for lang in ("c", "cpp", "rb", "swift") for form in ("comment", "string")
}


def test_precision_is_perfect(report: rb.Report) -> None:
    # Zero false positives apart from the documented fail-open cases above.
    fps = {c.id for c in report.cases if c.outcome == "FP"}
    assert fps == set(ACCEPTED_FP), sorted(fps ^ set(ACCEPTED_FP))
    tp = report.tp
    assert tp / (tp + report.fp - len(ACCEPTED_FP)) == MIN_PRECISION


def test_recall_above_floor(report: rb.Report) -> None:
    assert report.recall is not None
    assert report.recall >= MIN_RECALL, (
        report.recall,
        [c for c in report.cases if c.outcome == "FN"],
    )


def test_corpus_hash_file_matches_fixtures() -> None:
    # CORPUS.sha256 pins every label and fixture byte; regenerate with
    # `PYTHONPATH=src python benchmark/corpus/generate_fixtures.py --hash`.
    pinned = (rb.CORPUS_DIR / "CORPUS.sha256").read_text(encoding="utf-8")
    assert pinned == rb.corpus_listing(), "corpus changed without regenerating CORPUS.sha256"


def test_family_table_present(report: rb.Report) -> None:
    families = rb.report_to_dict(report)["per_family"]
    for fam in ("code.ts", "fs.cert", "fs.keystore", "fs.ssh", "net.tls", "fs.binary"):
        assert fam in families, sorted(families)
        assert {"tp", "fp", "fn", "tn", "precision", "recall"} <= families[fam].keys()


def test_accuracy_doc_names_current_corpus() -> None:
    # docs/ACCURACY.md must state the corpus it was measured on, on its first line.
    doc = (BENCHMARK_DIR.parent / "docs" / "ACCURACY.md").read_text(encoding="utf-8")
    assert rb.corpus_hash() in doc.splitlines()[0], "docs/ACCURACY.md is stale: re-run --by-family"
    assert "| family |" in doc


def test_no_case_errors(report: rb.Report) -> None:
    # A probe or fixture that raises is ERROR, not FN: it must fail the gate.
    assert not report.errors, [(c.id, c.note) for c in report.errors]


def test_raising_case_is_error_not_fn(tmp_path) -> None:  # type: ignore[no-untyped-def]
    case = {"id": "boom", "probe": "fs.cert.x509", "kind": "positive", "fixture": "nonsense", "input": "x"}
    r = rb.evaluate([case], corpus_dir=tmp_path)
    assert [c.outcome for c in r.cases] == ["ERROR"]
    assert (r.tp, r.fp, r.fn, r.tn, r.positives) == (0, 0, 0, 0, 0)
