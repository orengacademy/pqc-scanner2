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

Fixture kinds (manifest ``fixture:``)
-------------------------------------
- ``file`` (default): ``input`` is a file or directory; file probes get it as
  their roots / scan_paths.
- ``endpoint``: ``input`` is a YAML spec; the harness serves TLS from it on a
  free 127.0.0.1 port for the duration of the case and binds the probe to
  ``127.0.0.1:<port>`` exactly as ``--target`` does (``runner.bind_context``).
- ``image``: ``input`` is an OCI image layout directory; its layers are
  extracted in order into a temp rootfs and file probes are pointed at that
  (the ``docker export | pqcscan scan --path`` flow).

A case the host cannot serve (e.g. an endpoint needing OpenSSL >= 3.5) is
recorded as SKIP and excluded from every count. A case whose probe or fixture
raises is recorded as ERROR: excluded from the counts, listed separately, and a
failure of the run (exit 1; the pytest gate asserts there are none).

Families: a probe's family is its id up to the second dot (``fs.cert.x509`` ->
``fs.cert``); ``--by-family`` prints the aggregated table and the JSON report
always carries a ``per_family`` block.

Invoke with ``PYTHONPATH=src python benchmark/run_benchmark.py [--by-family]``.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import socket
import ssl
import sys
import tarfile
import tempfile
import threading
import warnings
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.types import Capability, Classification, Finding, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes._registry import Registry, default_registry
from pqcscan.runner.runner import bind_context

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


def corpus_listing(corpus_dir: Path = CORPUS_DIR) -> str:
    """sha256sum-format listing of manifest.yaml + every file under cases/, sorted by path.

    CORPUS.sha256 holds this text; the corpus hash is sha256(listing)."""
    files = [corpus_dir / "manifest.yaml", *(p for p in (corpus_dir / "cases").rglob("*") if p.is_file())]
    rows = sorted((p.relative_to(corpus_dir).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()) for p in files)
    return "".join(f"{digest}  {rel}\n" for rel, digest in rows)


def corpus_hash(corpus_dir: Path = CORPUS_DIR) -> str:
    return hashlib.sha256(corpus_listing(corpus_dir).encode()).hexdigest()


def family_of(probe_id: str) -> str:
    return ".".join(probe_id.split(".")[:2])


class UnservableFixtureError(Exception):
    """The host cannot serve this fixture; the case is excluded from scoring."""


def is_real_detection(finding: Finding) -> bool:
    """True when a finding is a real weak-crypto detection (not INFO/ERROR/PQC)."""
    return finding.classification in REAL_DETECTION_CLASSES


@dataclass(slots=True)
class CaseResult:
    id: str
    probe: str
    kind: str
    outcome: str  # "TP" | "FP" | "FN" | "TN" | "SKIP" | "ERROR"
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
    def errors(self) -> list[CaseResult]:
        return [c for c in self.cases if c.outcome == "ERROR"]

    @property
    def misclassified(self) -> list[str]:
        return [c.id for c in self.cases if c.outcome in {"FP", "FN"}]

    @property
    def families(self) -> dict[str, ProbeScore]:
        out: dict[str, ProbeScore] = {}
        for s in self.probes.values():
            f = out.setdefault(family_of(s.probe), ProbeScore(family_of(s.probe)))
            f.tp, f.fp, f.fn, f.tn = f.tp + s.tp, f.fp + s.fp, f.fn + s.fn, f.tn + s.tn
        return out


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


_TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


@contextlib.contextmanager
def tls_endpoint(spec_path: Path) -> Iterator[int]:
    """Serve TLS on a free 127.0.0.1 port from an endpoint spec; yield the port.

    Spec keys: cert, key (paths relative to the spec), min_version, max_version,
    optional ciphers (OpenSSL string), group (single TLS group, e.g. X25519),
    require_client_cert, requires_openssl ([major, minor])."""
    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    need = tuple(spec.get("requires_openssl") or ())
    if need and ssl.OPENSSL_VERSION_INFO[:len(need)] < need:
        raise UnservableFixtureError(f"needs OpenSSL >= {'.'.join(map(str, need))}, have {ssl.OPENSSL_VERSION}")
    base = spec_path.parent
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():  # TLSv1/1.1 are deprecated — serving them is the point
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = _TLS_VERSIONS[spec["min_version"]]
        ctx.maximum_version = _TLS_VERSIONS[spec["max_version"]]
    ctx.load_cert_chain(base / spec["cert"], base / spec["key"])
    if spec.get("ciphers"):
        ctx.set_ciphers(spec["ciphers"])
    if spec.get("group"):
        ctx.set_ecdh_curve(spec["group"])
    if spec.get("require_client_cert"):
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(base / spec["cert"])

    def handle(conn: socket.socket) -> None:
        conn.settimeout(5)
        with contextlib.suppress(OSError), conn, ctx.wrap_socket(conn, server_side=True) as tls:
            tls.recv(1)  # handshake, then wait for the client to hang up

    stop = threading.Event()
    srv = socket.create_server(("127.0.0.1", 0))
    srv.settimeout(0.1)

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        thread.join()
        srv.close()


def extract_oci_image(layout: Path, dest: Path) -> None:
    """Apply every layer of the (single-manifest) OCI layout at ``layout`` onto ``dest``."""
    def blob(digest: str) -> Path:
        algo, _, hexd = digest.partition(":")
        return layout / "blobs" / algo / hexd

    index = json.loads((layout / "index.json").read_text(encoding="utf-8"))
    manifest = json.loads(blob(index["manifests"][0]["digest"]).read_text(encoding="utf-8"))
    for layer in manifest["layers"]:
        # ponytail: no whiteout (.wh.*) handling; add it when a fixture needs multi-layer deletes.
        with tarfile.open(blob(layer["digest"]), mode="r:*") as tf:
            tf.extractall(dest, filter="data")


def _run_endpoint(registry: Registry, probe_id: str, spec_path: Path) -> list[Finding]:
    with tls_endpoint(spec_path) as port:
        ctx = ScanContext(
            scan_id=0, mode="root", available_capabilities=set(Capability),
            server_target=f"127.0.0.1:{port}",
        )
        probe = bind_context(registry.get(probe_id), ctx)
        collected: list[Finding] = []
        asyncio.run(asyncio.wait_for(probe.run(ctx, collected.append), timeout=60))
        return collected


def _run_case(registry: Registry, case: dict[str, Any], input_path: Path) -> list[Finding]:
    fixture = case.get("fixture", "file")
    if fixture == "endpoint":
        return _run_endpoint(registry, case["probe"], input_path)
    if fixture == "image":
        with tempfile.TemporaryDirectory(prefix="pqcscan-image-") as tmp:
            rootfs = Path(tmp)
            extract_oci_image(input_path, rootfs)
            return _run_probe(registry, case["probe"], rootfs)
    if fixture != "file":
        raise ValueError(f"unknown fixture kind {fixture!r}")
    return _run_probe(registry, case["probe"], input_path)


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
            all_findings = _run_case(registry, case, input_path)
            detections = [f for f in all_findings if is_real_detection(f)]
            outcome, note = _score_case(case, detections)
        except UnservableFixtureError as exc:
            outcome, note, detections = "SKIP", str(exc), []
        except Exception as exc:  # one bad case must not abort the run
            outcome, note, detections = "ERROR", f"{exc!r}", []
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
        if outcome in {"SKIP", "ERROR"}:
            continue
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


def _print_rows(label: str, rows: dict[str, ProbeScore], report: Report) -> None:
    header = f"{label:28s} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} {'precision':>10} {'recall':>10}"
    print(header)
    print("-" * len(header))
    for name in sorted(rows):
        s = rows[name]
        print(f"{name:28s} {s.tp:>3} {s.fp:>3} {s.fn:>3} {s.tn:>3} "
              f"{_fmt(s.precision):>10} {_fmt(s.recall):>10}")
    print("-" * len(header))
    print(f"{'OVERALL':28s} {report.tp:>3} {report.fp:>3} {report.fn:>3} {report.tn:>3} "
          f"{_fmt(report.precision):>10} {_fmt(report.recall):>10}")


def print_table(report: Report, by_family: bool = False) -> None:
    _print_rows("probe", report.probes, report)
    if by_family:
        print()
        _print_rows("family", report.families, report)
    skipped = [c for c in report.cases if c.outcome == "SKIP"]
    print(f"\ncases: {len(report.cases)}  "
          f"positives: {report.positives}  negatives: {report.negatives}  skipped: {len(skipped)}")
    for c in skipped:
        print(f"  [SKIP] {c.id} ({c.probe}): {c.note}")
    if report.errors:
        print(f"\nerrors ({len(report.errors)}):")
        for c in report.errors:
            print(f"  [ERROR] {c.id} ({c.probe}): {c.note}")
    misc = [c for c in report.cases if c.outcome in {"FP", "FN"}]
    if misc:
        print("\nmisclassified:")
        for c in misc:
            print(f"  [{c.outcome}] {c.id} ({c.probe}): {c.note}")
    else:
        print("\nmisclassified: none")


def _score_rows(rows: dict[str, ProbeScore]) -> dict[str, dict[str, Any]]:
    return {
        name: {"tp": s.tp, "fp": s.fp, "fn": s.fn, "tn": s.tn, "precision": s.precision, "recall": s.recall}
        for name, s in sorted(rows.items())
    }


def report_to_dict(report: Report) -> dict[str, Any]:
    return {
        "overall": {
            "tp": report.tp, "fp": report.fp, "fn": report.fn, "tn": report.tn,
            "precision": report.precision, "recall": report.recall,
            "positives": report.positives, "negatives": report.negatives,
            "cases": len(report.cases),
        },
        "corpus_sha256": corpus_hash(),
        "per_probe": _score_rows(report.probes),
        "per_family": _score_rows(report.families),
        "errors": [{"id": c.id, "probe": c.probe, "note": c.note} for c in report.errors],
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
    parser.add_argument("--by-family", action="store_true",
                        help="also print the per-family (probe id up to the second dot) table")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args(argv)

    cases = load_manifest(args.manifest)
    report = evaluate(cases, corpus_dir=args.manifest.resolve().parent)
    write_report(report)

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print_table(report, by_family=args.by_family)
        print(f"\ncorpus sha256: {corpus_hash()}")

    exit_code = 0
    if report.errors:
        print(f"\nFAIL: {len(report.errors)} case(s) raised (see errors)", file=sys.stderr)
        exit_code = 1
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
