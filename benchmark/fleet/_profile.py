"""Profile one load run: py-spy samples of the harness process (the collector runs in it), asyncio slow callbacks,
and statements per ingest as the database driver or server counts them. Output lands in one directory:
pyspy.collapsed.txt (collapsed stacks; speedscope.app opens it as a flame graph), asyncio-slow.log, statements.json,
auto_explain.log.gz (Postgres), summary.json, summary.md."""
from __future__ import annotations

import collections
import json
import os
import shutil
import signal
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

PTRACE_HINT = ("py-spy attaches with ptrace, which kernel.yama.ptrace_scope >= 1 reserves for root: "
               "run the harness as root or allow passwordless `sudo -n`")


@contextmanager
def pyspy(pid: int, out_dir: Path, rate: int = 100) -> Iterator[None]:
    """Record `pid` (all threads, non-idle) until the block ends, as collapsed stacks in pyspy.collapsed.txt.
    One recording only: two py-spy processes cannot ptrace the same pid at once. Not root: runs under `sudo -n`.
    Fails loudly, never silently produces an empty profile."""
    exe = shutil.which("py-spy", path=os.path.dirname(sys.executable)) or shutil.which("py-spy")
    if exe is None:
        raise RuntimeError("py-spy is not installed (pip install py-spy)")
    prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
    if prefix and subprocess.run([*prefix, "true"], capture_output=True).returncode != 0:
        raise RuntimeError(f"`sudo -n` failed; {PTRACE_HINT}")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "pyspy.collapsed.txt"
    p = subprocess.Popen([*prefix, exe, "record", "-p", str(pid), "--rate", str(rate), "--threads", "--format", "raw",
                          "-o", str(out)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        yield
    finally:
        p.send_signal(signal.SIGINT)                # py-spy flushes its output on interrupt; sudo relays the signal
        _, err = p.communicate(timeout=60)
        if p.returncode not in (0, -signal.SIGINT) or not out.exists():
            raise RuntimeError(f"py-spy failed ({p.returncode}): {err.decode()[-500:]}; {PTRACE_HINT}")


def top_frames(raw_path: Path, n: int = 10) -> list[dict]:
    """Self and total share per frame from py-spy's collapsed stacks (`frame;frame;... count`)."""
    self_c: collections.Counter[str] = collections.Counter()
    total_c: collections.Counter[str] = collections.Counter()
    samples = 0
    for line in raw_path.read_text().splitlines() if raw_path.exists() else []:
        stack, _, count = line.rpartition(" ")
        if not stack or not count.isdigit():
            continue
        c = int(count)
        samples += c
        frames = stack.split(";")
        self_c[frames[-1]] += c
        for f in set(frames):
            total_c[f] += c
    if not samples:
        return []
    rows = [{"frame": f, "self_pct": round(100 * self_c[f] / samples, 1),
             "total_pct": round(100 * total_c[f] / samples, 1)} for f in total_c]
    rows.sort(key=lambda r: (-r["self_pct"], -r["total_pct"], r["frame"]))
    return rows[:n]


def slow_callbacks(log_path: Path) -> dict:
    """asyncio's 'Executing <Handle ...> took N seconds' lines: count, max, top five."""
    rows = []
    if log_path.exists():
        for line in log_path.read_text().splitlines():
            if " took " in line and line.rstrip().endswith("seconds"):
                with suppress(ValueError):
                    rows.append((float(line.rsplit(" took ", 1)[1].split()[0]), line.strip()[:300]))
    rows.sort(reverse=True)
    return {"count": len(rows), "max_s": rows[0][0] if rows else 0.0, "top": [r[1] for r in rows[:5]]}


def summarise(profile_dir: Path, *, ingest_requests: int, enroll_requests: int, wall_s: float, run: dict) -> dict:
    """Write summary.json and summary.md from the files the run left in `profile_dir`; return the summary."""
    sp = profile_dir / "statements.json"
    stmts = json.loads(sp.read_text()) if sp.exists() else {}
    total = stmts.get("total_statements", 0)
    s = {
        "run": {k: run.get(k) for k in ("db", "hosts", "interval_s", "offered_rps", "rps", "p50_ms", "p95_ms",
                                         "findings_per_bundle", "commit", "src_hash", "box")},
        "wall_s": wall_s, "ingest_requests": ingest_requests, "enroll_requests": enroll_requests,
        "top_frames": top_frames(profile_dir / "pyspy.collapsed.txt", 10),
        "slow_callbacks": slow_callbacks(profile_dir / "asyncio-slow.log"),
        "statements_source": stmts.get("source"),
        "statements_total": total,
        "statements_per_ingest": round(total / ingest_requests, 1) if ingest_requests else None,
        "statements_note": "total statements over the run divided by ingest requests; enrolments are included "
                           f"({enroll_requests} enrolls)",
        "statements_top": stmts.get("top", [])[:25],
    }
    (profile_dir / "summary.json").write_text(json.dumps(s, indent=2) + "\n")
    top3 = s["top_frames"][:3]
    md = [f"# Profile: {run.get('db')} {run.get('hosts')} hosts at {run.get('offered_rps')} posts/s, "
          f"{run.get('findings_per_bundle')} findings per bundle", "",
          f"Commit `{str(run.get('commit'))[:9]}`, box {run.get('box')}, wall {wall_s:.0f} s, "
          f"ingest p50 {run.get('p50_ms')} ms, p95 {run.get('p95_ms')} ms.", "",
          "## Top three costs (share of sampled wall time, self)", "",
          "| frame | self % | total % |", "|---|---|---|",
          *[f"| `{t['frame']}` | {t['self_pct']} | {t['total_pct']} |" for t in top3], "",
          f"Statements per ingest: **{s['statements_per_ingest']}** ({s['statements_note']}; "
          f"source: {s['statements_source']}).", "",
          f"Slow event-loop callbacks (>= 100 ms): {s['slow_callbacks']['count']}, "
          f"max {s['slow_callbacks']['max_s']:.3f} s.", ""]
    (profile_dir / "summary.md").write_text("\n".join(md))
    return s
