"""Build docs/evidence/index.html from the campaign's committed artefacts.

    python -m benchmark.fleet.evidence_page

`load(repo_root)` reads the files and returns plain data; `render(data)` turns it into one self-contained HTML page
(inline CSS, no scripts, no network fonts). A missing input renders as "pending"; nothing here is typed in by hand
except the item wording that only exists in commit messages, and those rows name the commit as their source.
"""
import csv
import gzip
import json
import re
from datetime import date, timedelta
from pathlib import Path

from jinja2 import Environment
from markupsafe import Markup, escape

from benchmark.fleet import capacity as cap
from benchmark.fleet.run_load import accepted_percentiles

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


def _profile_run(root: Path, profile_dir: str, commit: str | None) -> dict:
    """The load result that wrote `profile_dir` at `commit` (the newest, if several): its stored scans and the
    p50/p95 of accepted (200) ingests, computed from its per-request CSV."""
    runs = [(r, f) for f in (root / RES).glob("load-*.json") if (r := _json(f) or {}).get("profile_dir") == profile_dir
            and commit and r.get("commit") == commit]
    if not runs:
        return {}
    r, f = max(runs, key=lambda x: x[0].get("started_at", ""))
    try:
        acc = accepted_percentiles(gzip.decompress((root / RES / r["requests_csv"]).read_bytes()))
    except (OSError, KeyError, TypeError):
        acc = {}
    return {"stored_scans": r.get("stored_scans"), **acc, "run_source": f"{RES}/{f.name}"}


def _profiles(root: Path) -> dict:
    out: dict = {}
    for p in sorted((root / "benchmark/fleet/profiles").glob("*-*/summary.json")):
        db, side = p.parent.name.rsplit("-", 1)
        s = _json(p) or {}
        run = s.get("run", {})
        out.setdefault(db, {})[side] = {
            "top": s.get("top_frames", [])[:3], "statements_per_ingest": s.get("statements_per_ingest"),
            "instrumentation_pct": s.get("instrumentation_pct"), "commit": (run.get("commit") or "")[:7],
            **_profile_run(root, str(p.parent.relative_to(root)), run.get("commit")),
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
    hosts, latest, growth = [], None, None
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
        if z.get("role") == "collector":
            growth = _db_growth(rows)
    hosts.sort(key=lambda h: (h["role"] != "collector", h["host"]))
    day = (latest - start).days if start and latest else None
    return {"start": start.isoformat() if start else None, "day": day,
            "day7": (start + timedelta(days=7)).isoformat() if start else None,
            "hosts": hosts, "observe": obs, "growth": growth,
            "windows": (root / RES / "soak-real" / "windows").is_dir()}


def _db_growth(rows: list[dict]) -> dict | None:
    """Collector DB plus WAL bytes per scan, from the first sample holding scans to the latest one."""
    def size(r: dict) -> int:
        return int(r.get("db_bytes") or 0) + int(r.get("wal_bytes") or 0)
    held = [r for r in rows if int(r.get("scans") or 0) > 0]
    if len(held) < 2 or int(held[-1]["scans"]) <= int(held[0]["scans"]):
        return None
    a, z = held[0], held[-1]
    return {"from_scans": int(a["scans"]), "scans": int(z["scans"]), "findings": int(z.get("findings") or 0),
            "db_mb": int(z["db_bytes"]) / 1e6, "wal_mb": int(z.get("wal_bytes") or 0) / 1e6, "at": z["ts"],
            "per_scan_mb": (size(z) - size(a)) / (int(z["scans"]) - int(a["scans"])) / 1e6}


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
        runs = [prof[db][side] for db in both for side in ("before", "after")]
        if all(r.get("p50_accepted_ms") is not None for r in runs):
            spi += (". Stored scans in the 300 s run and the median accepted (200) ingest: " + "; ".join(
                f"{db} {prof[db]['before']['stored_scans']} at {prof[db]['before']['p50_accepted_ms'] / 1000:.1f} s, "
                f"then {prof[db]['after']['stored_scans']} at {prof[db]['after']['p50_accepted_ms'] / 1000:.1f} s"
                for db in both) + ". Medians over every response count the 503s the queue sheds and are not quoted")
        srcs = ["benchmark/fleet/profiles/*/summary.json", *(r["run_source"] for r in runs if "run_source" in r)]
        i1 = ("ok", "Done", f"Before and after profiles for {', '.join(both)}: {spi}.", ", ".join(srcs))
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
        o, g = soak["observe"] or {}, soak["growth"]
        day_line = ""
        if o.get("scans_total") is not None and soak["day"] is not None:
            st = o.get("statuses", {})
            on_time = o["scans_total"] == (o.get("hosts_enrolled") or 0) * (soak["day"] + 1)
            day_line = (f" Day {soak['day']}: {o.get('hosts_enrolled')} hosts, {o['scans_total']} scans"
                        + (" (every host's daily scans arrived on schedule)" if on_time else "")
                        + f", drift {o.get('drift_rows_total')}, ingest {_codes(st.get('ingest'))}, "
                        f"enrol {_codes(st.get('enroll'))}.")
        if g:
            day_line += (f" Collector DB {g['db_mb']:.1f} MB and WAL {g['wal_mb']:.1f} MB at {g['scans']} scans and "
                         f"{g['findings']:,} findings: about {g['per_scan_mb']:.1f} MB per scan including WAL since "
                         f"the {g['from_scans']}-scan sample, against FLEET.md's 1.2 MB estimate; the final figure is "
                         "read at day 7.")
        i4 = ("ok" if done else "wait", "Done" if done else "Running",
              f"Running since {soak['start']}, day {soak['day']} recorded, day 7 on {soak['day7']}.{day_line} "
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
        adj["counts"] = _mutation_counts(mut, adj)
        mtxt += (f" Adjusted {adj['score']:.3f} = {adj['killed']} / {adj['denominator']}, {adj['rule']}: "
                 f"{adj['counts']}.")
    i5 = ("ok" if fuzz and mut else "wait", "Done" if fuzz and mut else "Partial", ftxt + mtxt,
          "benchmark/fleet/fuzz/stats.json, benchmark/fleet/mutation/score.json"
          + (", benchmark/fleet/mutation/MUTATION.md" if adj else ""))
    i6 = _item6(d)
    names = ["Profile before fixing", "Arrival model and capacity", "Overload behaviour", "Real soak, 7 days",
             "Test strength", "The two contradicted claims"]
    return [{"n": n, "item": name, "kind": k, "verdict": v, "basis": b, "source": s}
            for n, (name, (k, v, b, s)) in enumerate(zip(names, [i1, i2, i3, i4, i5, i6], strict=True), 1)]


def _codes(counts: dict | None) -> str:
    """{"200": 6} as "200 \u00d7 6" (the ledger's multiplication sign); none as "none"."""
    return ", ".join(f"{k} \u00d7 {v}" for k, v in sorted((counts or {}).items())) or "none"


def _non_503_failures(r: dict) -> int:
    """Locust failures that are not a 503 answer (timeouts, resets, other codes): `errors` minus the failure samples
    that carry a 503, such as a shed enrolment. Ingest 503s are counted apart (`http_503`) and are not failures."""
    shed = sum(int(m[1]) for f in r.get("failure_samples", []) if (m := re.search(r" 503: .*x(\d+)$", f)))
    return (r.get("errors") or 0) - shed


def _adjusted_mutation(md: str) -> dict | None:
    """The adjusted score line of MUTATION.md: `killed / (total - equivalent) = ... = K / N = S`."""
    m = re.search(r"Adjusted score[^:]*: (killed / \(total - equivalent\)) = .*?= (\d+) / (\d+) = (\d\.\d+)", md)
    if not m:
        return None
    row = {k: int(v) for k, v in re.findall(r"^\| (equivalent|open: message text|open: other) \| (\d+) \|$", md, re.M)}
    return {"rule": m[1], "killed": int(m[2]), "denominator": int(m[3]), "score": float(m[4]),
            "equivalent": row.get("equivalent"), "open_text": row.get("open: message text"),
            "open_other": row.get("open: other")}


def _mutation_counts(mut: dict, adj: dict) -> str:
    """"56 killed by the new tests, 14 equivalent, 41 message-text and 3 other open", from MUTATION.md's score table."""
    parts = [f"{adj['killed'] - mut['killed']} killed by the new tests"]
    if adj["equivalent"] is not None:
        parts.append(f"{adj['equivalent']} equivalent")
    if adj["open_text"] is not None and adj["open_other"] is not None:
        parts.append(f"{adj['open_text']} message-text and {adj['open_other']} other open")
    return ", ".join(parts)


def _commands(since: str | None) -> str | None:
    """The fenced bash block of the "Since PR #92" section: the commands a stranger runs."""
    m = re.search(r"^```bash\n(.*?)^```", since or "", re.M | re.S)
    return m[1].rstrip("\n") if m else None


def _item6(d: dict) -> tuple[str, str, str, str]:
    """Item 6 follows the F6 row of FLEET-EVIDENCE.md, so the verdict and the findings table cannot disagree. A fixed
    F6 reads "Done", the word the item table of FLEET-EVIDENCE.md uses; any other state is shown as written."""
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
    verdict = "Done" if kind == "ok" else f6["state"].split(" (")[0]
    return kind, verdict, text + pg, src + "; benchmark/fleet/profiles/postgres-*"


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
    env.filters.update(md=_md, n=_n, g=_g, kind=_state_kind, wbr=_wbr, unanswered=_non_503_failures)
    return env.from_string(TEMPLATE.read_text()).render(d=data, verdict=cap._pass_cell)


def main() -> None:
    out = ROOT / "docs/evidence/index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(load(ROOT)))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
