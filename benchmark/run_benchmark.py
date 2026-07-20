"""Accuracy-benchmark harness for pqcscan probes.

Runs every labelled case in ``benchmark/corpus/manifest.yaml`` against its probe
and computes per-probe and overall precision / recall. This turns "accurate"
from an asserted claim into a measured, regression-gated number.

Scoring — the "real detection" rule
------------------------------------
A probe often emits INFO / ERROR marker findings ("platform_info", "skipped",
"no X observed") and PQC_READY findings (already quantum-safe material). None of
those are weak-crypto detections. For benchmark scoring a probe is said to have
"fired" only when it emits at least one finding whose ``classification`` is a
real weak / quantum-vulnerable tier:

    {SANGAT_TINGGI, TINGGI, SEDERHANA, RENDAH}

(equivalently: ``severity.numeric >= LOW`` and ``classification != INFO``).

Confusion matrix
----------------
    positive + fired      -> TP        positive + not fired  -> FN
    negative + fired      -> FP        negative + not fired  -> TN

For a positive with an ``expect`` block, a fire only counts as TP when at least
one real finding also satisfies the refinement (algorithm substring and/or
minimum severity); otherwise it is an FN annotated "fired but wrong
algorithm/severity".

    precision = TP / (TP + FP)   (n/a when the probe predicted nothing positive)
    recall    = TP / (TP + FN)   (n/a when the probe has no positive cases)

Invoke with ``PYTHONPATH=src python benchmark/run_benchmark.py``.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.types import Capability, Classification, Finding, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes._registry import Registry, default_registry

# The four weak / quantum-vulnerable tiers that count as a real detection.
REAL_DETECTION_CLASSES: frozenset[Classification] = frozenset({
    Classification.SANGAT_TINGGI,
    Classification.TINGGI,
    Classification.SEDERHANA,
    Classification.RENDAH,
})

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.yaml"
REPORT_PATH = Path(__file__).resolve().parent / "last_report.json"


def is_real_detection(finding: Finding) -> bool:
    """True when a finding is a real weak-crypto detection (not INFO/ERROR/PQC)."""
    return finding.classification in REAL_DETECTION_CLASSES


@dataclass(slots=True)
class CaseResult:
    id: str
    probe: str
    kind: str
    outcome: str  # "TP" | "FP" | "FN" | "TN"
    fired: bool
    detections: list[str]  # algorithm names of real detections
    note: str = ""


@dataclass(slots=True)
class ProbeScore:
    probe: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return None if denom == 0 else self.tp / denom


@dataclass(slots=True)
class Report:
    cases: list[CaseResult] = field(default_factory=list)
    probes: dict[str, ProbeScore] = field(default_factory=dict)
    positives: int = 0
    negatives: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return None if denom == 0 else self.tp / denom

    @property
    def misclassified(self) -> list[str]:
        return [c.id for c in self.cases if c.outcome in {"FP", "FN"}]


def load_manifest(path: Path = MANIFEST_PATH) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        raise ValueError(f"manifest {path} must be a list of cases")
    return data


def _severity_at_least(finding: Finding, floor: str) -> bool:
    return finding.severity.numeric >= Severity(floor).numeric


def _satisfies_expect(detections: list[Finding], expect: dict[str, Any]) -> bool:
    """True when at least one real detection meets every refinement in expect."""
    want_alg = expect.get("algorithm_contains")
    want_sev = expect.get("min_severity")
    for f in detections:
        if want_alg is not None and want_alg.lower() not in f.algorithm.lower():
            continue
        if want_sev is not None and not _severity_at_least(f, want_sev):
            continue
        return True
    return False


def _run_probe(registry: Registry, probe_id: str, input_path: Path) -> list[Finding]:
    """Point the probe at ``input_path`` and collect its findings."""
    probe = registry.get(probe_id)
    if hasattr(probe, "roots"):
        probe.roots = [input_path]
    scan_dir = input_path if input_path.is_dir() else input_path.parent
    scan_paths = [input_path]
    if scan_dir != input_path:
        scan_paths.append(scan_dir)
    ctx = ScanContext(
        scan_id=0,
        mode="root",
        available_capabilities=set(Capability),
        scan_paths=scan_paths,
    )
    collected: list[Finding] = []
    asyncio.run(probe.run(ctx, collected.append))
    return collected


def _score_case(case: dict[str, Any], detections: list[Finding]) -> tuple[str, str]:
    """Return (outcome, note) for one case given its real detections."""
    kind = case["kind"]
    fired = bool(detections)
    if kind == "positive":
        if not fired:
            return "FN", "expected a detection, none fired"
        expect = case.get("expect") or {}
        if expect and not _satisfies_expect(detections, expect):
            got = ", ".join(f"{f.algorithm}/{f.severity.value}" for f in detections)
            return "FN", f"fired but wrong algorithm/severity (got {got}; want {expect})"
        return "TP", ""
    # negative
    if fired:
        got = ", ".join(f"{f.algorithm}/{f.severity.value}" for f in detections)
        return "FP", f"false positive: fired {got}"
    return "TN", ""


def evaluate(
    cases: list[dict[str, Any]],
    corpus_dir: Path = CORPUS_DIR,
    registry: Registry | None = None,
) -> Report:
    registry = registry or default_registry()
    report = Report()
    for case in cases:
        input_path = (corpus_dir / case["input"]).resolve()
        try:
            all_findings = _run_probe(registry, case["probe"], input_path)
            detections = [f for f in all_findings if is_real_detection(f)]
            outcome, note = _score_case(case, detections)
        except Exception as exc:  # one bad case must not abort the run
            outcome, note, detections = "FN", f"error: {exc!r}", []
        result = CaseResult(
            id=case["id"],
            probe=case["probe"],
            kind=case["kind"],
            outcome=outcome,
            fired=bool(detections),
            detections=[f.algorithm for f in detections],
            note=note,
        )
        report.cases.append(result)
        score = report.probes.setdefault(case["probe"], ProbeScore(case["probe"]))
        setattr(score, outcome.lower(), getattr(score, outcome.lower()) + 1)
        setattr(report, outcome.lower(), getattr(report, outcome.lower()) + 1)
        if case["kind"] == "positive":
            report.positives += 1
        else:
            report.negatives += 1
    return report


# --------------------------------------------------------------------------- IO


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:6.3f}"


def print_table(report: Report) -> None:
    header = f"{'probe':24s} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} {'precision':>10} {'recall':>10}"
    print(header)
    print("-" * len(header))
    for probe in sorted(report.probes):
        s = report.probes[probe]
        print(f"{probe:24s} {s.tp:>3} {s.fp:>3} {s.fn:>3} {s.tn:>3} "
              f"{_fmt(s.precision):>10} {_fmt(s.recall):>10}")
    print("-" * len(header))
    print(f"{'OVERALL':24s} {report.tp:>3} {report.fp:>3} {report.fn:>3} {report.tn:>3} "
          f"{_fmt(report.precision):>10} {_fmt(report.recall):>10}")
    print(f"\ncases: {len(report.cases)}  "
          f"positives: {report.positives}  negatives: {report.negatives}")
    misc = [c for c in report.cases if c.outcome in {"FP", "FN"}]
    if misc:
        print("\nmisclassified:")
        for c in misc:
            print(f"  [{c.outcome}] {c.id} ({c.probe}): {c.note}")
    else:
        print("\nmisclassified: none")


def report_to_dict(report: Report) -> dict[str, Any]:
    return {
        "overall": {
            "tp": report.tp, "fp": report.fp, "fn": report.fn, "tn": report.tn,
            "precision": report.precision, "recall": report.recall,
            "positives": report.positives, "negatives": report.negatives,
            "cases": len(report.cases),
        },
        "per_probe": {
            p: {
                "tp": s.tp, "fp": s.fp, "fn": s.fn, "tn": s.tn,
                "precision": s.precision, "recall": s.recall,
            }
            for p, s in sorted(report.probes.items())
        },
        "misclassified": [
            {"id": c.id, "probe": c.probe, "outcome": c.outcome, "note": c.note}
            for c in report.cases if c.outcome in {"FP", "FN"}
        ],
        "cases": [asdict(c) for c in report.cases],
    }


def write_report(report: Report, path: Path = REPORT_PATH) -> None:
    with path.open("w", encoding="utf-8") as fh:
        json.dump(report_to_dict(report), fh, indent=2)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pqcscan accuracy benchmark")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    parser.add_argument("--min-precision", type=float, default=None,
                        help="fail (exit 1) if overall precision < this")
    parser.add_argument("--min-recall", type=float, default=None,
                        help="fail (exit 1) if overall recall < this")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args(argv)

    cases = load_manifest(args.manifest)
    report = evaluate(cases, corpus_dir=args.manifest.resolve().parent)
    write_report(report)

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print_table(report)

    exit_code = 0
    if args.min_precision is not None:
        prec = report.precision if report.precision is not None else 0.0
        if prec < args.min_precision:
            print(f"\nFAIL: precision {prec:.3f} < required {args.min_precision:.3f}", file=sys.stderr)
            exit_code = 1
    if args.min_recall is not None:
        rec = report.recall if report.recall is not None else 0.0
        if rec < args.min_recall:
            print(f"\nFAIL: recall {rec:.3f} < required {args.min_recall:.3f}", file=sys.stderr)
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
