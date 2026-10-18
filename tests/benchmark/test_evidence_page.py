import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import evidence_page

REPO = Path(__file__).resolve().parents[2]

LEDGER = """# Fleet mode evidence

## Findings

| ID | Finding | Severity | State | Owner | Source |
|---|---|---|---|---|---|
| F6 | **Windows installer half-writes on `-RunAs`.** More text. | Medium | Fixed | Packaging | task 7 |
| F20 | Postgres is no faster than SQLite. | Medium | Open | Product | LOAD.md |

## Not run here
"""


def _sweep(db, rate, seed, p95):
    return {"schema_version": 2, "db": db, "offered_rps": rate, "seed": seed, "p95_ms": p95, "requests": 100,
            "pass_p95_lt_2s": p95 < 2000, "measurement_defect": False, "hosts": 500}


def _tree(tmp_path: Path) -> Path:
    fl = tmp_path / "benchmark" / "fleet"
    res = fl / "results"
    (res / "soak-real").mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "FLEET-EVIDENCE.md").write_text(LEDGER)
    for i, (rate, p95) in enumerate([(1, 300), (2, 900), (4, 2600)]):
        for seed in (1, 2):
            (res / f"load-sqlite-20261019-{i}-s{seed}-sweep.json").write_text(json.dumps(_sweep("sqlite", rate, seed, p95)))
    (res / "soak-real-20261018.json").write_text(json.dumps({
        "started_at": "2026-10-18T13:43:46+00:00",
        "cycles": [{"hosts_enrolled": 3, "scans_total": 3, "drift_rows_total": 0,
                    "statuses": {"ingest": {"200": 3}, "enroll": {"201": 3}}}]}))
    head = "ts,role,load1,mem_used_kb,mem_avail_kb,disk_used_kb,db_bytes,wal_bytes,state_bytes,spool_files,hosts,scans,findings\n"
    (res / "soak-real" / "ubuntu-samples.csv").write_text(
        head + "2026-10-18T13:23:05Z,agent,0.80,1,1,1,,,1908779,0,,,\n2026-10-19T13:30:01Z,agent,0.00,1,1,1,,,1908779,0,,,\n")
    for side in ("before", "after"):
        d = fl / "profiles" / f"sqlite-{side}"
        d.mkdir(parents=True)
        (d / "summary.json").write_text(json.dumps({
            "run": {"p95_ms": 60000.0 if side == "before" else 35000.0, "rps": 1.2},
            "top_frames": [{"frame": f"frame{i} ({side})", "self_pct": 10.0 - i, "total_pct": 10.0} for i in range(5)],
            "statements_per_ingest": 8528.2, "instrumentation_pct": 20.2}))
    (res / "ci-runs.json").write_text(json.dumps({
        "windows_installer_f6": {"run": 39131286228, "commit": "6c694c6", "result": "31/31 on both runners"}}))
    for db, head, base in (("sqlite", 150.0, 190.0), ("postgres", 710.0, 810.0)):
        (res / f"ci-baseline-{db}.json").write_text(json.dumps({"db": db, "hosts": 60, "p95_ms": head, "rps": 1.0}))
        (res / f"ci-baseline-77867a1-{db}.json").write_text(json.dumps({"db": db, "p95_ms": base}))
    (fl / "fuzz").mkdir()
    (fl / "fuzz" / "stats.json").write_text(json.dumps([
        {"harness": "json", "cpu_seconds": 7200, "execs": 10, "crashes": 0, "corpus_files": 4},
        {"harness": "raw", "cpu_seconds": 7200, "execs": 20, "crashes": 0, "corpus_files": 2}]))
    (fl / "fuzz" / "coverage.txt").write_text(
        "Name  Stmts   Miss  Cover   Missing\n---\nsrc/pqcscan/store/bundle.py     105     19    82%   62\n"
        "---\nTOTAL   105  19  82%\n")
    return tmp_path


def test_load_reads_every_input_and_marks_missing_mutation_pending(tmp_path):
    d = evidence_page.load(_tree(tmp_path))
    assert d["mutation"] is None
    assert d["capacity"]["sqlite"]["lambda_max"] == 2 and d["capacity"]["sqlite"]["band"] == [2, 4]
    assert [f["frame"] for f in d["profiles"]["sqlite"]["before"]["top"]] == [f"frame{i} (before)" for i in range(3)]
    assert d["fuzz"]["cpu_hours"] == 4.0 and d["fuzz"]["coverage"][0]["cover"] == 82
    assert d["soak"]["day"] == 1 and d["soak"]["day7"] == "2026-10-25"
    assert d["soak"]["hosts"][0]["host"] == "ubuntu" and d["soak"]["hosts"][0]["samples"] == 2
    assert [f["id"] for f in d["findings"]] == ["F6", "F20"]
    assert d["findings"][0]["title"] == "Windows installer half-writes on -RunAs."
    assert [i["n"] for i in d["items"]] == [1, 2, 3, 4, 5, 6]
    assert "Do not tag" in d["tag"]


def test_render_has_item_table_capacity_row_source_cells_and_pending_mutation(tmp_path):
    html = evidence_page.render(evidence_page.load(_tree(tmp_path)))
    assert 'id="items"' in html and html.count('<tr class="item') == 6
    assert re.search(r'<tr class="cap">.*?sqlite.*?</tr>', html, re.S)
    assert 'class="src"' in html and "load-sqlite-20261019-0-s1-sweep.json" in html
    mutation = html[html.index('id="strength"'):]
    assert "pending" in mutation[:mutation.index("</section>")].lower()
    assert "1,908,779" in html or "ubuntu" in html  # the soak host row
    assert "{{" not in html and "}}" not in html and "{%" not in html  # no template text leaks into the page
    assert "load-sqlite-<wbr>-*-sweep*.json" not in html and "results/<wbr>load-sqlite-*-sweep*.json" in html


def test_ci_ratio_reads_the_base_side_file(tmp_path):
    ci = {r["db"]: r for r in evidence_page.load(_tree(tmp_path))["ci"]}
    assert ci["sqlite"]["base_p95_ms"] == 190.0 and ci["sqlite"]["ratio"] == 0.79
    assert ci["postgres"]["ratio"] == 0.88 and "ci-baseline-77867a1-postgres.json" in ci["postgres"]["source"]


def test_item_6_follows_the_f6_row(tmp_path):
    root = _tree(tmp_path)
    item6 = evidence_page.load(root)["items"][5]
    assert (item6["kind"], item6["verdict"]) == ("ok", "Fixed")
    assert "39131286228" in item6["basis"] and "ci-runs.json" in item6["source"]
    ledger = root / "docs" / "FLEET-EVIDENCE.md"
    ledger.write_text(ledger.read_text().replace("| Medium | Fixed | Packaging |", "| Medium | Open | Packaging |"))
    d = evidence_page.load(root)
    assert (d["items"][5]["kind"], d["items"][5]["verdict"]) == ("bad", "Open")
    assert "39131286228" not in d["items"][5]["basis"]


def test_empty_tree_renders_pending_everywhere_without_crashing(tmp_path):
    html = evidence_page.render(evidence_page.load(tmp_path))
    assert "<title>" in html and html.lower().count("pending") >= 4


def test_the_committed_page_has_no_external_scripts():
    html = evidence_page.render(evidence_page.load(REPO))
    allowed = ("https://cdnjs.cloudflare.com/", "https://cdn.jsdelivr.net/npm/", "https://unpkg.com/")
    srcs = re.findall(r'<script[^>]*\ssrc="([^"]+)"', html)
    assert all(s.startswith(allowed) for s in srcs) and not srcs
    assert "ubuntu" in html and 'id="capacity"' in html
    assert "1,908,779" in html  # ubuntu agent state bytes from results/soak-real/ubuntu-samples.csv
    d = evidence_page.load(REPO)
    f6 = next(f for f in d["findings"] if f["id"] == "F6")
    assert d["items"][5]["verdict"] == f6["state"].split(" (")[0]
    assert (REPO / "docs/evidence/index.html").read_text() == html  # the committed page is a fresh regeneration
