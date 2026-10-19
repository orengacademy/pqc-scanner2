import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmark.fleet import ratio


def _w(p, p95, **extra):
    p.write_text(json.dumps({"p50_ms": 100, "p95_ms": p95, "rps": 2.0, "errors": 0, **extra}))
    return p


def test_ratio_passes_under_floor_and_fails_past_ratio(tmp_path):
    base = _w(tmp_path / "b.json", 400)
    assert ratio.verdict(base, _w(tmp_path / "h1.json", 900), max_ratio=1.5, floor_ms=1000) == 0   # 2.25x but < 1 s
    assert ratio.verdict(base, _w(tmp_path / "h2.json", 1200), max_ratio=1.5, floor_ms=1000) == 1  # 3x and > 1 s
    base2, head3 = _w(tmp_path / "b2.json", 1500), _w(tmp_path / "h3.json", 2000)
    assert ratio.verdict(base2, head3, max_ratio=1.5, floor_ms=1000) == 0


def test_ratio_boundary_is_inclusive(tmp_path):
    base = _w(tmp_path / "b.json", 2000)
    assert ratio.verdict(base, _w(tmp_path / "h1.json", 3000), max_ratio=1.5, floor_ms=1000) == 0
    assert ratio.verdict(base, _w(tmp_path / "h2.json", 3001), max_ratio=1.5, floor_ms=1000) == 1


def test_table_reads_both_result_shapes(tmp_path, capsys):
    base = _w(tmp_path / "b.json", 400)  # PR #92 shape: no littles_ratio or measurement_defect
    head = _w(tmp_path / "h.json", 450, requests=170, littles_ratio=1.0, measurement_defect=False)
    assert ratio.main([str(base), str(head), "--max-ratio", "1.5", "--floor-ms", "1000"]) == 0
    out = capsys.readouterr().out
    for key in ("p50_ms", "p95_ms", "rps", "errors", "littles_ratio", "measurement_defect"):
        assert key in out


def test_missing_or_non_file_path_fails_clearly(tmp_path):
    ok = _w(tmp_path / "ok.json", 400)
    for bad in (tmp_path / "nope.json", tmp_path, Path("")):
        with pytest.raises(SystemExit) as e:
            ratio.main([str(bad), str(ok)])
        assert "no result file" in str(e.value)
        with pytest.raises(SystemExit):
            ratio.main([str(ok), str(bad)])


def test_saturated_baseline_is_inconclusive_not_a_pass(tmp_path, capsys):
    head = _w(tmp_path / "h.json", 100)  # would pass any ratio
    slow = _w(tmp_path / "b1.json", 5001)
    assert ratio.verdict(slow, head, max_ratio=1.5, floor_ms=1000) == 1
    assert "baseline saturated on this runner; ratio inconclusive" in capsys.readouterr().out
    lost = _w(tmp_path / "b2.json", 400, hosts=60, interval_s=60.0)  # rps 2.0 offered 1.0: fine
    assert ratio.verdict(lost, head, max_ratio=1.5, floor_ms=1000) == 0
    lost = _w(tmp_path / "b3.json", 400, hosts=60, interval_s=60.0, rps=0.89)  # below 0.9 x 1.0
    assert ratio.verdict(lost, head, max_ratio=1.5, floor_ms=1000) == 1
    assert "inconclusive" in capsys.readouterr().out


def test_errors_or_503s_on_either_side_fail_the_unsaturated_gate(tmp_path, capsys):
    ok = _w(tmp_path / "ok.json", 400)
    for side, extra in (("base", {"errors": 2}), ("head", {"http_503": 1})):
        bad = _w(tmp_path / f"{side}.json", 400, **extra)
        args = (bad, ok) if side == "base" else (ok, bad)
        assert ratio.verdict(*args, max_ratio=1.5, floor_ms=1000) == 1
        out = capsys.readouterr().out
        assert f"{side} answered" in out and "every request" in out and "PASS" not in out
