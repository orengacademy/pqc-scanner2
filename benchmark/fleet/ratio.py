"""Compare two load-harness result files and gate on p95.

    python -m benchmark.fleet.ratio BASE.json HEAD.json --max-ratio 1.5 --floor-ms 1000

Exits 0 when head p95 <= max(max_ratio x base p95, floor_ms), else 1. The floor keeps a fast baseline from turning
runner noise into a failure. Keys a result file lacks (the PR #92 harness has no littles_ratio or measurement_defect)
are left out of the table.

Precondition: when the baseline itself saturated the runner (rps < 0.9 x offered, offered = hosts / interval_s, or
p95 > 5 s) the ratio only measures queueing, so the run is inconclusive and exits 1 with a message saying so.
"""
import argparse
import json
from pathlib import Path

SATURATED_P95_MS = 5000
SATURATED_RPS_FRACTION = 0.9
ROWS = ("p50_ms", "p95_ms", "rps", "errors", "requests", "littles_ratio", "measurement_defect")


def _cell(v) -> str:
    return "-" if v is None else f"{v:.6g}" if isinstance(v, float) else str(v)


def _ratio(b, h) -> str:
    ok = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (b, h))
    return f"{h / b:.2f}x" if ok and b else "-"


def verdict(base: Path, head: Path, *, max_ratio: float, floor_ms: float) -> int:
    for p in (base, head):
        if not Path(p).is_file():
            raise SystemExit(f"ratio: no result file at {str(p)!r}")
    b, h = (json.loads(Path(p).read_text()) for p in (base, head))
    offered = b["hosts"] / b["interval_s"] if b.get("hosts") and b.get("interval_s") else None
    saturated = b["p95_ms"] > SATURATED_P95_MS or (offered is not None and b["rps"] < SATURATED_RPS_FRACTION * offered)
    limit = max(max_ratio * b["p95_ms"], floor_ms)
    print(f"{'':20}{'base':>12}{'head':>12}{'ratio':>9}")
    for k in ROWS:
        if k in b or k in h:
            print(f"{k:20}{_cell(b.get(k)):>12}{_cell(h.get(k)):>12}{_ratio(b.get(k), h.get(k)):>9}")
    if saturated:
        print(f"baseline saturated on this runner; ratio inconclusive (base p95 {b['p95_ms']:.0f} ms, base rps "
              f"{b['rps']:.3g} vs offered {_cell(offered)}; limits: p95 <= {SATURATED_P95_MS} ms, rps >= "
              f"{SATURATED_RPS_FRACTION:g} x offered)")
        return 1
    ok = h["p95_ms"] <= limit
    print(f"head p95 {h['p95_ms']:.0f} ms vs limit {limit:.0f} ms "
          f"(max of {max_ratio:g} x base p95 {b['p95_ms']:.0f} ms and {floor_ms:.0f} ms): {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("base", type=Path)
    ap.add_argument("head", type=Path)
    ap.add_argument("--max-ratio", type=float, default=1.5)
    ap.add_argument("--floor-ms", type=float, default=1000)
    a = ap.parse_args(argv)
    return verdict(a.base, a.head, max_ratio=a.max_ratio, floor_ms=a.floor_ms)


if __name__ == "__main__":
    raise SystemExit(main())
