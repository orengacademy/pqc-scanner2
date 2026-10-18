"""Derive the collector's sustainable ingest rate from the load sweep and write CAPACITY.md.

    python -m benchmark.fleet.capacity

Reads results/load-*.json by file name: `-sweep` (rate sweep), `-herd` (all hosts at once), `-par` (Postgres ingest
parallelism), `-pginsert` (Postgres insert strategy), each matched as a whole name segment. Rows older than schema 2
(the PR #92 runs) are ignored. Rows run at an ingest parallelism other than the shipped default are kept apart as
superseded and never set λ_max. A row with `measurement_defect` True or None is excluded from the rule: True means
requests were lost, None means Little's law could not be checked. Only True also counts as a failure when placing
the upper edge of the band.
"""
import argparse
import contextlib
import json
import re
from pathlib import Path

from pqcscan.daemon.fleet import INGEST_PARALLELISM, INGEST_PARALLELISM_PG

HERE = Path(__file__).resolve().parent
P95_LIMIT_MS = 2000
RES = "benchmark/fleet/results"
TAGS = ("-sweep", "-herd", "-par", "-pginsert")
SHIPPED_SLOTS = {"sqlite": INGEST_PARALLELISM, "postgres": INGEST_PARALLELISM_PG}


def _verdict(r: dict) -> str:
    if r.get("measurement_defect") is not False:
        return "excluded"
    return "pass" if r["pass_p95_lt_2s"] else "fail"


def _with_reason(r: dict) -> dict:
    if r.get("measurement_defect") is None:
        why = "Little's law could not be checked (per-host interval longer than half the run)"
    else:
        why = r.get("measurement_defect_reason") or "measurement defect"
    return {**r, "excluded_reason": why}


def capacity(results: list[dict]) -> dict:
    out = {}
    for db in sorted({r["db"] for r in results}):
        mine = [r for r in results if r["db"] == db]
        slots = SHIPPED_SLOTS.get(db)
        rows = sorted((r for r in mine if r.get("ingest_parallelism", slots) == slots),
                      key=lambda r: (r["offered_rps"], r["seed"], r.get("hosts", 0)))
        superseded = sorted((r for r in mine if r not in rows),
                            key=lambda r: (r["offered_rps"], r["seed"], r.get("hosts", 0)))
        by_rate: dict[float, list[dict]] = {}
        for r in rows:
            by_rate.setdefault(r["offered_rps"], []).append(r)
        passing, failing = [], []
        for rate, rs in by_rate.items():
            verdicts = [_verdict(r) for r in rs]
            # rows with measurement_defect None are ignored for the verdict; a rate needs passes on two distinct seeds
            if any(r.get("measurement_defect") is True for r in rs) or "fail" in verdicts:
                failing.append(rate)
            elif len({r["seed"] for r, v in zip(rs, verdicts, strict=True) if v == "pass"}) >= 2:
                passing.append(rate)
        fail_rate = min(failing, default=None)
        # a rate above the first failure does not count: capacity is where the curve is still under the line
        lam = max((p for p in passing if fail_rate is None or p < fail_rate), default=None)
        out[db] = {
            "lambda_max": lam, "band": [lam, fail_rate],
            "hosts_daily_2h": None if lam is None else round(lam * 7200),
            "hosts_daily_24h": None if lam is None else round(lam * 86400),
            "rows": rows, "superseded": superseded,
            "excluded": [_with_reason(r) for r in rows if _verdict(r) == "excluded"],
        }
    return out


def _pass_cell(r: dict) -> str:
    v = _verdict(r)
    if v == "excluded":
        return "excluded (unmeasured)" if r.get("measurement_defect") is None else "excluded (defect)"
    return v.upper()


def _num(x, fmt="{}"):
    return "-" if x is None else fmt.format(x)


def _sweep_table(rows: list[dict]) -> list[str]:
    head = ["rate (posts/s)", "hosts", "seed", "commit", "requests", "p50 ms", "p95 ms", "p99 ms", "achieved rps",
            "Little ratio", "429", "503", "errors", "result"]
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        g = r.get
        cells = [f"{r['offered_rps']:g}", _num(g("hosts")), r["seed"], g("commit", "-")[:7], r["requests"],
                 _num(g("p50_ms"), "{:.0f}"), f"{r['p95_ms']:.0f}", _num(g("p99_ms"), "{:.0f}"), _num(g("rps")),
                 _num(g("littles_ratio")),
                 _num(g("http_429")), _num(g("http_503")), _num(g("errors")), _pass_cell(r)]
        out.append("| " + " | ".join(str(c) for c in cells) + " |")
    return out


def _backend(db: str, c: dict) -> list[str]:
    out = [f"## {db}", "", *_sweep_table(c["rows"]), ""]
    lam, fail = c["band"]
    if lam is None:
        out.append("**λ_max: none.** No swept rate passed on both seeds"
                   + (f"; the lowest failure is {fail:g} posts/s." if fail is not None else "."))
    else:
        upper = f"{fail:g}" if fail is not None else "the top of the sweep (no rate failed)"
        out.append(f"**λ_max = {lam:g} posts/s** (band {lam:g} to {upper}). Under the daily timer with a 2 h jitter "
                   f"that is about {c['hosts_daily_2h']:,} hosts; spread over 24 h, about {c['hosts_daily_24h']:,}.")
    if c["excluded"]:
        out += ["", "Excluded from the rule:"]
        out += [f"- {r['offered_rps']:g} posts/s, seed {r['seed']}: {r['excluded_reason']}" for r in c["excluded"]]
    return [*out, ""]


def _no_response(r: dict) -> int:
    """Ingest requests that got no HTTP answer (locust status 0: timeout or reset), from the failure samples."""
    hits = (re.search(r"ingest 0: .*x(\d+)$", f) for f in r.get("failure_samples", []))
    return sum(int(m.group(1)) for m in hits if m)


def _backend_summary(caps: dict) -> list[str]:
    out = ["| backend | λ_max (posts/s) | band | hosts/day, 2 h jitter | hosts/day, spread over 24 h |",
           "|---|---|---|---|---|"]
    for db, c in caps.items():
        lam, fail = c["band"]
        low = min(r["offered_rps"] for r in c["rows"])
        lam_cell = f"{lam:g}" if lam is not None else f"below {low:g}"
        band = "none passed" if lam is None else f"{lam:g} to {_num(fail, '{:g}')}"
        daily = [f"{c[k]:,}" if c[k] is not None else "-" for k in ("hosts_daily_2h", "hosts_daily_24h")]
        out.append(f"| {db} | {lam_cell} | {band} | {daily[0]} | {daily[1]} |")
    return [*out, ""]


def _ci_paragraph(caps: dict, ci: dict) -> list[str]:
    out = []
    for db, c in caps.items():
        mine = ci.get(db)
        at1 = [r["p95_ms"] for r in c["rows"] if r["offered_rps"] == 1]
        if mine and at1:
            out.append(f"- {db}: runner p95 {mine['p95_ms']:g} ms ({mine['hosts']} hosts); this box p95 "
                       f"{min(at1):g} to {max(at1):g} ms ({min(at1) / mine['p95_ms']:.1f} to "
                       f"{max(at1) / mine['p95_ms']:.1f} times slower).")
    if not out:
        return []
    return ["## Against the CI runner", "",
            "The load-ratio CI job runs the same harness on a GitHub `ubuntu-latest` runner "
            "(`results/ci-baseline-*.json`), 1 post/s, 60 hosts, 1,670-finding bundles. Both backends meet p95 < 2 s "
            "there with room to spare:", "", *out, "",
            "So the λ_max figures describe this box class. They are not a limit of the collector on faster cores, "
            "and one CI rate is not a sweep.", ""]


def _finding_f23(prof: dict, p50s: list[float]) -> list[str]:
    b, a = prof.get("before"), prof.get("after")
    if not (b and a):
        return []
    svc = f"{min(p50s) / 1000:g} to {max(p50s) / 1000:g} s" if p50s else "not measured"
    wait_b, wait_a = (_num(x["wait_total_pct"], "{:g}") for x in (b, a))
    return ["## F23: Postgres ingest cost per row", "",
            f"The profile at `{a['commit']}` (`profiles/postgres-after`) shows {a['statements_per_ingest']:,.0f} "
            f"statements per ingest, against {b['statements_per_ingest']:,.0f} at `{b['commit']}` "
            "(`profiles/postgres-before`). The statements are one INSERT per findings row and per framework-view "
            "row through the psycopg pipeline, plus one foreign-key check per inserted row. Time inside psycopg's "
            f"`wait` is {wait_b} % of sampled wall time before and {wait_a} % after. The single-ingest service "
            f"time is the Postgres p50 at the lowest swept rate, where nothing queues: {svc}. Two slots divide that, "
            "so Postgres saturates below the SQLite rate and meets no swept p95 target on this box.", "",
            "Proposed fix, out of scope for this branch: bulk-load findings with `COPY` or batched inserts, and "
            "defer the foreign-key checks to the end of the transaction. Neither is tried here.", ""]


def render(res: dict[str, list[dict]], ci: dict | None = None, prof: dict | None = None) -> str:
    sweep, herd, par, pginsert = (res.get(t, []) for t in TAGS)
    caps = capacity(sweep)
    box = next((r["box"] for r in sweep if r.get("box")), None)
    box_txt = (f"{box['cpus']} vCPU, {box['mem_gb']} GB, `cpu_model: {box['cpu_model']}` (a shared-CPU DigitalOcean "
               "droplet with slow cores)") if box else "an 8-vCPU droplet"
    md = ["# Fleet ingest capacity", "",
          "Generated by `python -m benchmark.fleet.capacity` from `results/load-*.json` (name segments `sweep`, "
          "`herd`, `par`, `pginsert`) and the profiles. Do not edit by hand.", ""]
    if caps:
        md += ["## Result", "", *_backend_summary(caps),
               "Measured on " + box_txt + ", locust and the collector on one host over loopback, 1,670-finding "
               "bundles, p95 < 2 s. The figures are for this box class (see the CI comparison below).", ""]
    md += ["## Method", "",
           "Open arrival: each host enrols and posts at a random offset within its interval, so the offered load is a "
           "steady λ posts/s. Each post is a 1,670-finding bundle. Every run lasts 300 s and is repeated with two "
           "seeds. The rule: λ_max is the largest swept rate at which both seeds have p95 below 2 s and a sound "
           "measurement, with no higher rate failing; the band's upper edge is the lowest rate where any seed "
           "fails or loses requests. Little's law (hosts / (interval + mean latency) against the achieved rate) "
           "decides whether requests were lost. It cannot be checked when a host's interval exceeds half the run, "
           "so the host count follows the rate: 60 hosts at 0.5 posts/s (120 s interval), 100 at 1 (100 s), 250 at 2 "
           "(125 s), 300 at 3 (100 s), 500 at 4 and above. The first SQLite pass at 2 posts/s used 500 hosts, a 250 s "
           "interval; its `measurement_defect` is `None`, so those rows are listed as excluded and the 250-host rows "
           "decide that rate. The Postgres 500-host rows at 2 posts/s are 4-slot rows (see the superseded section), "
           "not passes. The SQLite rows come from two code commits, shown in the commit column (`2a25807` for "
           "all but the 250- and 300-host rows at 2 and 3 posts/s, which are `04c2650`). The SQLite ingest code is "
           "identical between them: under `src/` only the Postgres slot default (and a comment) and UI files "
           "changed. The capacity tables come from unprofiled runs at the shipped ingest parallelism (2 slots on "
           "both backends). Profiled runs carry asyncio debug-mode overhead and their "
           "latencies are not capacity numbers.", ""]
    if not caps:
        md += ["No sweep results exist yet.", ""]
    for db, c in caps.items():
        md += _backend(db, c)
    md += ["## Herd (all 500 hosts at once)", ""]
    if herd:
        md += ["| db | requests | 503 | no response | p95 ms | enrol p95 ms | enrol 503 |",
               "|---|---|---|---|---|---|---|"]
        md += [f"| {r['db']} | {r['requests']} | {_num(r.get('http_503'))} | {_no_response(r)} | {r['p95_ms']:.0f} "
               f"| {_num(r.get('enroll_p95_ms'), '{:.0f}')} | {_num(r.get('enroll_503'))} |" for r in herd]
        md += ["", "`503` is the bounded ingest queue shedding load; `no response` counts ingests that timed out or "
               "were reset. Little's law is not applied: a herd is not a steady arrival."
               + (" Every p95 is below the agent's 60 s request timeout." if all(r["p95_ms"] < 60000 for r in herd)
                  else ""), ""]
    else:
        md += ["No herd results exist yet.", ""]
    sup = [r for c in caps.values() for r in c["superseded"]]
    md += ["## Superseded and diagnostic runs", "",
           "Not capacity numbers. The 4-slot Postgres default was replaced by 2 slots after these runs "
           "(`INGEST_PARALLELISM_PG`), so rows at another slot count do not set λ_max. The 500-host runs below are "
           "all at 4 posts/s or more, far past saturation on both backends: they compare settings, not capacity."]
    if sup:
        md += ["", "Sweep rows at the old 4-slot default:", "", *_sweep_table(sup)]
    md += ["", "Four 4-slot Postgres rows were overwritten by the 2-slot re-sweep under the same file names. They ran "
           "at code `2a25807` and survive in git: `git show f0955d9:benchmark/fleet/results/<file>` for "
           "`load-postgres-20261018-60h-r0.5-sweep.json` and `load-postgres-20261018-60h-r0.5-sweep-2.json` "
           "(p95 7.5 and 8.8 s at 0.5 posts/s), `load-postgres-20261018-100h-r1-sweep.json` and "
           "`load-postgres-20261018-100h-r1-sweep-2.json` (p95 47 and 50 s at 1 post/s).", "",
           "### Postgres ingest parallelism (500 hosts)", ""]
    if par:
        md += ["| rate (posts/s) | slots | p95 ms | achieved rps | Little ratio | result |",
               "|---|---|---|---|---|---|"]
        md += [f"| {r['offered_rps']:g} | {r['ingest_parallelism']} | {r['p95_ms']:.0f} | {_num(r.get('rps'))} "
               f"| {_num(r.get('littles_ratio'))} | {_pass_cell(r)} |"
               for r in sorted(par, key=lambda r: (r["offered_rps"], r["ingest_parallelism"]))]
    else:
        md.append("No parallelism results exist yet.")
    md += ["", "### Postgres insert strategy (500 hosts, 4 posts/s)", ""]
    if pginsert:
        md += ["| insert | slots | p95 ms | achieved rps | Little ratio | 503 | errors | result |",
               "|---|---|---|---|---|---|---|---|"]
        md += [f"| {r.get('insert_mode', '-')} | {r['ingest_parallelism']} | {r['p95_ms']:.0f} | {_num(r.get('rps'))} "
               f"| {_num(r.get('littles_ratio'))} | {_num(r.get('http_503'))} | {_num(r.get('errors'))} "
               f"| {_pass_cell(r)} |"
               for r in sorted(pginsert, key=lambda r: (r.get("insert_mode", ""), r["ingest_parallelism"]))]
    else:
        md.append("No insert-strategy results exist yet.")
    pg_rows = caps.get("postgres", {}).get("rows", [])
    low = [r["p50_ms"] for r in pg_rows if r["offered_rps"] == min((x["offered_rps"] for x in pg_rows), default=0)]
    md += ["", *_finding_f23((prof or {}).get("postgres", {}), low), *_ci_paragraph(caps, ci or {})]
    md += ["## The PR #92 rows", "",
           "500 hosts every 60 s was 8.3 posts/s, about 60,000 daily hosts under FLEET.md's timer; at FLEET.md's "
           "2,000 hosts the offered rate is 0.28 posts/s.", ""]
    return "\n".join(md)


def load(results_dir: Path = HERE / "results") -> dict[str, list[dict]]:
    """Schema-2 load results by tag. A tag matches a whole segment of the file name, so `-par` never matches a longer
    word. A re-run of the same point (same backend, rate, hosts, seed, slots, insert mode) replaces the earlier one.
    Each row carries `_file` and `_src` (its repo path)."""
    found: dict[str, dict[tuple, dict]] = {t: {} for t in TAGS}
    for f in sorted(results_dir.glob("load-*.json")):
        r = json.loads(f.read_text())
        if r.get("schema_version", 0) < 2:
            continue
        for tag, rows in found.items():
            if tag[1:] in f.stem.split("-"):
                key = (r["db"], r.get("offered_rps"), r.get("hosts"), r["seed"], r.get("ingest_parallelism"),
                       r.get("insert_mode"))
                rows[key] = {**r, "_file": f.name, "_src": f"{RES}/{f.name}"}
    return {t: list(rows.values()) for t, rows in found.items()}


def load_ci(results_dir: Path = HERE / "results") -> dict[str, dict]:
    """The CI load-ratio job's head-side result per backend, if its file is committed."""
    out = {}
    for db in ("sqlite", "postgres"):
        with contextlib.suppress(OSError, ValueError):
            out[db] = json.loads((results_dir / f"ci-baseline-{db}.json").read_text())
    return out


def load_profiles(profiles_dir: Path = HERE / "profiles") -> dict[str, dict]:
    """Per backend and side: commit, statements per ingest and the total share of psycopg's `wait` frame."""
    out: dict = {}
    for p in sorted(profiles_dir.glob("postgres-*/summary.json")):
        s = json.loads(p.read_text())
        wait = next((f["total_pct"] for f in s.get("top_frames", []) if f["frame"].startswith("wait ")), None)
        out.setdefault("postgres", {})[p.parent.name.rsplit("-", 1)[1]] = {
            "commit": s["run"]["commit"][:7], "statements_per_ingest": s["statements_per_ingest"],
            "wait_total_pct": wait}
    return out


def main() -> None:
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    out = HERE / "CAPACITY.md"
    res = load()
    out.write_text(render(res, load_ci(), load_profiles()))
    print(f"wrote {out}: " + ", ".join(f"{len(rows)} {t[1:]}" for t, rows in res.items()))


if __name__ == "__main__":
    main()
