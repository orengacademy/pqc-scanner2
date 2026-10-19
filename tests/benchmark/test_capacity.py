import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import capacity


def row(db, rate, seed, p95, defect=False):
    return {"db": db, "offered_rps": rate, "seed": seed, "p95_ms": p95, "pass_p95_lt_2s": p95 < 2000,
            "measurement_defect": defect, "arrival": "staggered", "requests": 100}


def test_lambda_max_needs_both_seeds_and_no_defect():
    rows = [row("sqlite", 1, 1, 300), row("sqlite", 1, 2, 320),
            row("sqlite", 2, 1, 900), row("sqlite", 2, 2, 950),
            row("sqlite", 4, 1, 1500), row("sqlite", 4, 2, 2600),
            row("sqlite", 8, 1, 9000, defect=True), row("sqlite", 8, 2, 9500, defect=True)]
    c = capacity.capacity(rows)["sqlite"]
    assert c["lambda_max"] == 2 and c["band"] == [2, 4]
    assert c["hosts_daily_2h"] == 14400 and c["hosts_daily_24h"] == 172800
    assert [r["offered_rps"] for r in c["excluded"]] == [8, 8]


def test_unmeasured_none_is_excluded_and_is_not_a_capacity_failure():
    rows = [row("sqlite", 0.5, 1, 100, defect=None), row("sqlite", 0.5, 2, 110),
            row("sqlite", 1, 1, 300), row("sqlite", 1, 2, 320)]
    c = capacity.capacity(rows)["sqlite"]
    assert c["lambda_max"] == 1 and c["band"] == [1, None]
    assert [r["offered_rps"] for r in c["excluded"]] == [0.5]
    assert "Little" in c["excluded"][0]["excluded_reason"]


def test_a_rate_with_one_seed_does_not_count_and_dbs_stay_apart():
    rows = [row("sqlite", 1, 1, 300), row("sqlite", 1, 2, 320), row("sqlite", 2, 1, 500),
            row("postgres", 1, 1, 5000), row("postgres", 1, 2, 5000)]
    c = capacity.capacity(rows)
    assert c["sqlite"]["lambda_max"] == 1 and c["sqlite"]["band"] == [1, None]
    assert c["postgres"]["lambda_max"] is None and c["postgres"]["band"] == [None, 1]
    assert c["postgres"]["hosts_daily_2h"] is None


def test_no_results_renders_a_file_saying_so():
    md = capacity.render({})
    assert "No sweep results" in md


def test_rows_at_another_slot_count_are_superseded_not_counted():
    ok = [{**row("postgres", 1, s, 300), "ingest_parallelism": 2} for s in (1, 2)]
    old = [{**row("postgres", 2, s, 300), "ingest_parallelism": 4} for s in (1, 2)]
    c = capacity.capacity(ok + old)["postgres"]
    assert c["lambda_max"] == 1 and c["band"] == [1, None]
    assert [r["offered_rps"] for r in c["rows"]] == [1, 1] and [r["offered_rps"] for r in c["superseded"]] == [2, 2]


def test_load_matches_whole_name_segments_and_keeps_both_host_counts(tmp_path):
    import json

    def put(name, **kw):
        (tmp_path / name).write_text(json.dumps({**row("sqlite", 2, 1, 300), "schema_version": 2, **kw}))
    put("load-sqlite-20261018-250h-r2-sweep.json", hosts=250)
    put("load-sqlite-20261018-r2-sweep.json", hosts=500)        # same rate, db and seed, other host count
    put("load-sqlite-20261018-r4-par.json", ingest_parallelism=3)
    put("load-sqlite-20261018-parade.json")                      # "par" is only part of this word
    put("load-sqlite-20261017-sweep.json", schema_version=1)     # PR #92 format
    res = capacity.load(tmp_path)
    assert sorted(r["hosts"] for r in res["-sweep"]) == [250, 500]
    assert [r["_file"] for r in res["-par"]] == ["load-sqlite-20261018-r4-par.json"]
    assert res["-herd"] == [] and res["-pginsert"] == []


def test_both_seeds_means_two_distinct_seeds_not_two_rows():
    rows = [{**row("sqlite", 2, 1, 900), "hosts": 250}, {**row("sqlite", 2, 1, 950), "hosts": 400}]
    c = capacity.capacity(rows)["sqlite"]
    assert c["lambda_max"] is None and c["band"] == [None, None]
    c = capacity.capacity([*rows, row("sqlite", 2, 2, 920)])["sqlite"]
    assert c["lambda_max"] == 2


def test_unmeasured_rows_at_a_rate_do_not_veto_two_passing_seeds():
    rows = [{**row("sqlite", 2, s, 900), "hosts": 250} for s in (1, 2)]
    rows += [{**row("sqlite", 2, s, 1300, defect=None), "hosts": 500} for s in (1, 2)]
    c = capacity.capacity(rows)["sqlite"]
    assert c["lambda_max"] == 2 and c["band"] == [2, None]
    assert [r["hosts"] for r in c["excluded"]] == [500, 500]
    # a real failure at the same rate still wins over the passes
    c = capacity.capacity([*rows, {**row("sqlite", 2, 1, 2500), "hosts": 250, "seed": 3}])["sqlite"]
    assert c["lambda_max"] is None and c["band"] == [None, 2]


def test_cli_help_prints_help_and_does_not_regenerate(capsys, monkeypatch):
    import pytest
    monkeypatch.setattr(sys, "argv", ["capacity", "--help"])
    with pytest.raises(SystemExit) as e:
        capacity.main()
    assert e.value.code == 0 and "CAPACITY.md" in capsys.readouterr().out


def test_commit_filter_scores_one_run_alone(tmp_path):
    import json

    def put(name, commit, p95):
        (tmp_path / name).write_text(json.dumps({**row("sqlite", 2, 1, p95), "schema_version": 2, "commit": commit}))
    put("load-sqlite-20261018-r2-sweep.json", "aaaa1111", 300)            # committed, passing
    put("load-sqlite-20261019-r2-sweep.json", "bbbb2222", 2500)           # a stranger's run, failing
    assert [r["commit"] for r in capacity.load(tmp_path, commit="bbbb")["-sweep"]] == ["bbbb2222"]
    assert len(capacity.load(tmp_path)["-sweep"]) == 1                    # unfiltered: same point, newest file wins
    md = capacity.render(capacity.load(tmp_path, commit="bbbb"), commit="bbbb")
    assert "Scored from only the rows run at commit `bbbb`" in md
