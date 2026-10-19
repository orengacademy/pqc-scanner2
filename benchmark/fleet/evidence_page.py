"""Build docs/evidence/index.html from the campaign's committed artefacts.

    python -m benchmark.fleet.evidence_page

`load(repo_root)` reads the files and returns plain data; `render(data)` turns it into one self-contained HTML page
(inline CSS, no scripts, no network fonts). A missing input renders as "pending"; nothing here is typed in by hand
except the item wording that only exists in commit messages, and those rows name the commit as their source.
"""
import csv
import json
import re
from datetime import date, timedelta
from pathlib import Path

from jinja2 import Environment
from markupsafe import Markup, escape

from benchmark.fleet import capacity as cap

ROOT = Path(__file__).resolve().parents[2]
RES = "benchmark/fleet/results"


def _json(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def _results(root: Path) -> dict[str, list[dict]]:
    """Schema-2 load results by tag (capacity.load), each row carrying `_file` and `_src` for the source cell."""
    return cap.load(root / RES)


def _profiles(root: Path) -> dict:
    out: dict = {}
    for p in sorted((root / "benchmark/fleet/profiles").glob("*-*/summary.json")):
        db, side = p.parent.name.rsplit("-", 1)
        s = _json(p) or {}
        run = s.get("run", {})
        out.setdefault(db, {})[side] = {
            "top": s.get("top_frames", [])[:3], "statements_per_ingest": s.get("statements_per_ingest"),
            "instrumentation_pct": s.get("instrumentation_pct"), "p95_ms": run.get("p95_ms"), "rps": run.get("rps"),
            "source": str(p.relative_to(root))}
    return out


def _soak(root: Path) -> dict:
    jsons = sorted((root / RES).glob("soak-real-*.json"))
    obs = None
    start = None
    if jsons:
        first, last = _json(jsons[0]) or {}, _json(jsons[-1]) or {}
        if first.get("started_at"):
            start = date.fromisoformat(first["started_at"][:10])
        cyc = (last.get("cycles") or [{}])[-1]
        obs = {"hosts_enrolled": cyc.get("hosts_enrolled"), "scans_total": cyc.get("scans_total"),
               "drift_rows_total": cyc.get("drift_rows_total"), "statuses": cyc.get("statuses", {}),
               "source": f"{RES}/{jsons[-1].name}"}
    hosts, latest = [], None
    for f in sorted((root / RES / "soak-real").glob("*-samples.csv")):
        rows = list(csv.DictReader(f.open()))
        if not rows:
            continue
        a, z = rows[0], rows[-1]
        size = z.get("db_bytes") or z.get("state_bytes")
        hosts.append({"host": f.name.removesuffix("-samples.csv"), "role": z.get("role", ""), "samples": len(rows),
                      "first": a["ts"], "last": z["ts"], "spool": z.get("spool_files") or None,
                      "bytes": int(size) if size else None, "scans": z.get("scans") or None,
                      "source": f"{RES}/soak-real/{f.name}"})
        d = date.fromisoformat(z["ts"][:10])
        latest = d if latest is None or d > latest else latest
        start = start or date.fromisoformat(a["ts"][:10])
    hosts.sort(key=lambda h: (h["role"] != "collector", h["host"]))
    day = (latest - start).days if start and latest else None
    return {"start": start.isoformat() if start else None, "day": day,
            "day7": (start + timedelta(days=7)).isoformat() if start else None,
            "hosts": hosts, "observe": obs, "windows": (root / RES / "soak-real" / "windows").is_dir()}


def _fuzz(root: Path) -> dict | None:
    stats = _json(root / "benchmark/fleet/fuzz/stats.json")
    if not stats:
        return None
    cov = []
    try:
        for line in (root / "benchmark/fleet/fuzz/coverage.txt").read_text().splitlines():
            m = re.match(r"(src/\S+)\s+(\d+)\s+(\d+)\s+(\d+)%", line)
            if m:
                cov.append({"file": m[1], "stmts": int(m[2]), "miss": int(m[3]), "cover": int(m[4])})
    except OSError:
        pass
    return {"harnesses": stats, "cpu_hours": round(sum(h["cpu_seconds"] for h in stats) / 3600, 1),
            "execs": sum(h["execs"] for h in stats), "crashes": sum(h["crashes"] for h in stats), "coverage": cov}


def _ci(root: Path) -> list[dict]:
    """Head side `ci-baseline-<db>.json` against base side `ci-baseline-77867a1-<db>.json` of the same CI run."""
    out = []
    for db in ("sqlite", "postgres"):
        head = _json(root / RES / f"ci-baseline-{db}.json")
        if not head:
            continue
        base = _json(root / RES / f"ci-baseline-77867a1-{db}.json") or {}
        b = base.get("p95_ms")
        out.append({"db": db, "hosts": head.get("hosts"), "offered_rps": head.get("offered_rps"),
                    "p95_ms": head["p95_ms"], "base_p95_ms": b, "ratio": round(head["p95_ms"] / b, 2) if b else None,
                    "rps": head.get("rps"),
                    "source": f"{RES}/ci-baseline-{db}.json"
                              + (f", {RES}/ci-baseline-77867a1-{db}.json" if b else "; base side pending")})
    return out


def _ui(root: Path) -> list[dict]:
    t = _json(root / "benchmark/fleet/ui/timings.json")
    if not t:
        return []
    src = "benchmark/fleet/ui/timings.json"
    rows = [{"what": p["page"], "seconds": p["ttfb_ms"] / 1000, "kind": "first byte", "bytes": p.get("transfer_bytes"),
             "source": src} for p in t.get("pages", [])]
    for e in t.get("exports", []):
        if e.get("status") == 200:
            s = e.get("curl_total_s_median", e.get("curl_total_s"))
            rows.append({"what": e["endpoint"], "seconds": s, "kind": "complete", "bytes": e.get("bytes"),
                         "source": src})
    return rows


def _md_tables(text: str) -> list[list[list[str]]]:
    """Every pipe table in `text` as rows of cells, separator rows dropped."""
    tables, cur = [], []
    for line in [*text.splitlines(), ""]:
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                cur.append(cells)
        elif cur:
            tables.append(cur)
            cur = []
    return tables


def _section(md: str, title: str) -> str | None:
    m = re.search(rf"^## {re.escape(title)}.*?$(.*?)(?=^## |\Z)", md, re.M | re.S)
    return m[1] if m else None


def _findings(md: str) -> list[dict]:
    sec = _section(md, "Findings") or ""
    out = []
    for t in _md_tables(sec):
        if t[0][:2] != ["ID", "Finding"]:
            continue
        col = {h: i for i, h in enumerate(t[0])}
        for r in t[1:]:
            text = r[col["Finding"]]
            m = re.match(r"\*\*(.+?)\*\*", text)
            title = m[1] if m else re.split(r"(?<=\.)\s", text, maxsplit=1)[0]
            out.append({"id": r[0], "title": title.replace("`", ""), "severity": r[col["Severity"]],
                        "state": r[col["State"]], "source": r[col["Source"]]})
    return out


def _state_kind(state: str) -> str:
    s = state.lower()
    return "ok" if s.startswith("fixed") and "residual" not in s else "bad" if s.startswith("open") else "wait"


def _items(d: dict) -> list[dict]:
    prof, caps, soak, fuzz, res = d["profiles"], d["capacity"], d["soak"], d["fuzz"], d["results"]
    both = [db for db, p in prof.items() if {"before", "after"} <= p.keys()]
    if both:
        spi = "; ".join(f"{db} {prof[db]['before']['statements_per_ingest']:,.0f} to "
                        f"{prof[db]['after']['statements_per_ingest']:,.0f} statements per ingest" for db in both)
        i1 = ("ok", "Done", f"Before and after profiles for {', '.join(both)}: {spi}.",
              "benchmark/fleet/profiles/*/summary.json")
    else:
        i1 = ("wait", "Pending", "Before and after profiles are not both present.", "benchmark/fleet/profiles/")
    if caps:
        txt = "; ".join(
            f"{db} λ_max {_g(c['lambda_max'])} posts/s (band {_g(c['band'][0])} to {_g(c['band'][1])})"
            if c["lambda_max"] is not None else f"{db}: no swept rate passed, lowest failure {_g(c['band'][1])} posts/s"
            for db, c in caps.items())
        i2 = ("ok", "Measured", txt + ".", f"{RES}/load-*-sweep*.json")
    else:
        i2 = ("wait", "Pending",
              "No sweep result files yet, so there is no capacity number. CAPACITY.md waits on them.",
              f"{RES}/load-*-sweep*.json")
    herd = res["-herd"]
    queue = ("The bounded ingest queue answers 503 with Retry-After past 32 waiting bundles, before reading the body; "
             "a unit test drives it full and sees the 503.")
    if herd:
        lost = [(r, _non_503_failures(r)) for r in herd]
        counts = "; ".join(f"{r['db']} {n} of {r.get('requests') or 0}" for r, n in lost)
        src3 = ", ".join(r["_src"] for r in herd)
        lost_txt = queue + f" Herd requests that got neither an answer nor a 503: {counts}"
        if all(n == 0 for _, n in lost):
            i3 = ("ok", "Holds", queue + " Every herd failure is a 503.", src3)
        elif all(n < 0.01 * (r.get("requests") or 0) and (r.get("p95_ms") or 0) < 60000 for r, n in lost):
            i3 = ("ok", "Holds, residual F24",
                  lost_txt + ", each under 1 %, and every herd p95 is below the agent's 60 s timeout.", src3)
        else:
            i3 = ("bad", "Fails",
                  lost_txt + "; at 1 % or more, or a herd p95 at or past the agent's 60 s timeout.", src3)
    else:
        i3 = ("wait", "Partial", queue + " Herd result pending.", "commits aaa9c0c, 6e7d8a4; daemon/fleet.py")
    linux = [h["host"] for h in soak["hosts"] if h["role"] == "agent"]
    if soak["start"]:
        done = soak["day"] is not None and soak["day"] >= 7 and soak["windows"]
        i4 = ("ok" if done else "wait", "Done" if done else "Running",
              f"Running since {soak['start']}, day {soak['day']} recorded, day 7 on {soak['day7']}. "
              f"Linux agents: {', '.join(linux) or 'none'}. Windows Server 2022 and 2025 runners join when PR #93 "
              "merges. GitHub offers no Windows 11 runner. IBM i is untested.",
              f"{RES}/soak-real-*.json, {RES}/soak-real/*-samples.csv, commit ed7a795")
    else:
        i4 = ("wait", "Pending", "No real soak data yet.", f"{RES}/soak-real/")
    mut = d["mutation"]
    ftxt = (f"atheris {fuzz['cpu_hours']:g} CPU-hours, {fuzz['execs']:,} executions, {fuzz['crashes']} crashes. "
            if fuzz else "Fuzz stats pending. ")
    adj = d["mutation_adjusted"]
    mtxt = (f"Mutation score {mut['score']:.3f} raw ({mut['killed']} of {mut['total']} killed in the mutmut run)."
            if mut else "Mutation score pending (the mutmut run was relaunched).")
    if mut and adj:
        mtxt += f" Adjusted {adj['score']:.3f} = {adj['killed']} / {adj['denominator']}, {adj['rule']}."
    i5 = ("ok" if fuzz and mut else "wait", "Done" if fuzz and mut else "Partial", ftxt + mtxt,
          "benchmark/fleet/fuzz/stats.json, benchmark/fleet/mutation/score.json"
          + (", benchmark/fleet/mutation/MUTATION.md" if adj else ""))
    i6 = _item6(d)
    names = ["Profile before fixing", "Arrival model and capacity", "Overload behaviour", "Real soak, 7 days",
             "Test strength", "The two contradicted claims"]
    return [{"n": n, "item": name, "kind": k, "verdict": v, "basis": b, "source": s}
            for n, (name, (k, v, b, s)) in enumerate(zip(names, [i1, i2, i3, i4, i5, i6], strict=True), 1)]


def _non_503_failures(r: dict) -> int:
    """Locust failures that are not a 503 answer (timeouts, resets, other codes): `errors` minus the failure samples
    that carry a 503, such as a shed enrolment. Ingest 503s are counted apart (`http_503`) and are not failures."""
    shed = sum(int(m[1]) for f in r.get("failure_samples", []) if (m := re.search(r" 503: .*x(\d+)$", f)))
    return (r.get("errors") or 0) - shed


def _adjusted_mutation(md: str) -> dict | None:
    """The adjusted score line of MUTATION.md: `killed / (total - equivalent) = ... = K / N = S`."""
    m = re.search(r"Adjusted score[^:]*: (killed / \(total - equivalent\)) = .*?= (\d+) / (\d+) = (\d\.\d+)", md)
    return {"rule": m[1], "killed": int(m[2]), "denominator": int(m[3]), "score": float(m[4])} if m else None


def _commands(since: str | None) -> str | None:
    """The fenced bash block of the "Since PR #92" section: the commands a stranger runs."""
    m = re.search(r"^```bash\n(.*?)^```", since or "", re.M | re.S)
    return m[1].rstrip("\n") if m else None


def _item6(d: dict) -> tuple[str, str, str, str]:
    """Item 6 follows the F6 row of FLEET-EVIDENCE.md, so the verdict and the findings table cannot disagree."""
    f6 = next((f for f in d["findings"] if f["id"] == "F6"), None)
    src = "docs/FLEET-EVIDENCE.md (F6 row)"
    pg = (" Postgres: profiled before and after (benchmark/fleet/profiles/postgres-*)."
          if {"before", "after"} <= d["profiles"].get("postgres", {}).keys() else " Postgres profile pending.")
    if f6 is None:
        return "wait", "Pending", "No F6 row in the findings table of FLEET-EVIDENCE.md." + pg, src
    kind = _state_kind(f6["state"])
    text = f"F6 (Windows installer, non-SYSTEM -RunAs) is {f6['state'].lower()} in FLEET-EVIDENCE.md."
    run = d["ci_runs"].get("windows_installer_f6")
    if kind == "ok" and run:
        text += f" Pester {run['result']}, CI run {run['run']} at {run['commit']}."
        src += f"; {RES}/ci-runs.json"
    return kind, f6["state"].split(" (")[0], text + pg, src + "; benchmark/fleet/profiles/postgres-*"


def _g(x) -> str:
    return f"{x:g}" if isinstance(x, (int, float)) else "-"  # None, or a key the template found missing


def load(repo_root: Path = ROOT) -> dict:
    root = Path(repo_root)
    try:
        ledger = (root / "docs/FLEET-EVIDENCE.md").read_text()
    except OSError:
        ledger = ""
    res = _results(root)
    caps = cap.capacity(res["-sweep"])
    for c in caps.values():
        c["files"] = [r["_file"] for r in c["rows"]]
    mut = _json(root / "benchmark/fleet/mutation/score.json")
    try:
        adjusted = _adjusted_mutation((root / "benchmark/fleet/mutation/MUTATION.md").read_text())
    except OSError:
        adjusted = None
    since = _section(ledger, "Since PR #92")
    d = {"results": res, "capacity": caps, "profiles": _profiles(root), "soak": _soak(root), "fuzz": _fuzz(root),
         "mutation": mut if isinstance(mut, dict) and "score" in mut else None, "ci": _ci(root), "ui": _ui(root),
         "findings": _findings(ledger), "since": _md_tables(since) if since else None, "commands": _commands(since),
         "mutation_adjusted": adjusted,
         "ci_runs": _json(root / RES / "ci-runs.json") or {}}
    d["items"] = _items(d)
    blocking = [i for i in d["items"][:4] if i["kind"] != "ok"]
    d["tag_ok"] = not blocking
    d["tag"] = ("Items 1 to 4 hold. The spec allows tagging v0.10.3." if not blocking else
                "Do not tag v0.10.3 yet. The spec holds the tag until items 1 to 4 hold. Not yet holding: "
                + "; ".join(f"item {i['n']} ({i['verdict'].lower()})" for i in blocking) + ".")
    return d


def _md(s) -> Markup:
    """Escape, then the two inline marks the ledger uses: `code` and **bold**."""
    h = str(escape(s))
    h = re.sub(r"`([^`]+)`", r"<code>\1</code>", h)
    return Markup(re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", h))


def _wbr(s) -> Markup:
    """Line-break opportunities after each slash, so a long path wraps at a directory, not mid-name."""
    return Markup(str(escape(s)).replace("/", "/<wbr>"))


def _n(x, fmt="{:,}") -> str:
    return fmt.format(x) if isinstance(x, (int, float)) else "-"


TEMPLATE = Path(__file__).with_name("evidence_page.html.j2")


def render(data: dict) -> str:
    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    env.filters.update(md=_md, n=_n, g=_g, kind=_state_kind, wbr=_wbr)
    return env.from_string(TEMPLATE.read_text()).render(d=data, verdict=cap._pass_cell)


def main() -> None:
    out = ROOT / "docs/evidence/index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(load(ROOT)))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
