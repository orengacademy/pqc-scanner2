"""Mosca X+Y>Z shelf-life calculator + its report-context wiring."""
from __future__ import annotations

from pqcscan.core.mosca import MoscaInputs, MoscaResult, assess, summary_lines
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.renderers._report_context import build_report_context
from pqcscan.store.repo import Repo


def test_at_risk_when_sum_exceeds_threat() -> None:
    r = assess(MoscaInputs(data_lifetime_years=25, migration_years=5, threat_years=10))
    assert r.sum_xy == 30
    assert r.gap_years == 20
    assert r.at_risk is True
    assert r.verdict == "at-risk"


def test_ok_when_sum_below_threat() -> None:
    r = assess(MoscaInputs(data_lifetime_years=2, migration_years=3, threat_years=10))
    assert r.gap_years == -5
    assert r.at_risk is False
    assert r.verdict == "ok"


def test_boundary_equal_is_not_at_risk() -> None:
    # X+Y == Z : migration finishes exactly as the threat arrives → gap 0, ok.
    r = assess(MoscaInputs(data_lifetime_years=5, migration_years=5, threat_years=10))
    assert r.gap_years == 0
    assert r.at_risk is False
    assert r.verdict == "ok"


def test_defaults_applied_when_only_x_given() -> None:
    r = assess(MoscaInputs(data_lifetime_years=8))
    assert r.y == 5.0        # default migration_years
    assert r.z == 10.0       # default threat_years
    assert r.sum_xy == 13
    assert r.at_risk is True


def test_result_as_dict_roundtrips() -> None:
    r = assess(MoscaInputs(data_lifetime_years=10))
    d = r.as_dict()
    assert isinstance(r, MoscaResult)
    assert d["x"] == 10.0 and d["gap_years"] == 5.0 and d["verdict"] == "at-risk"


def test_summary_lines_are_bilingual_and_deterministic() -> None:
    r = assess(MoscaInputs(data_lifetime_years=25, migration_years=5, threat_years=10))
    lines = summary_lines(r, vulnerable_count=3)
    assert set(lines) == {"en", "ms"}
    assert "shelf-life gap of 20" in lines["en"]
    assert "jurang jangka-hayat 20" in lines["ms"]
    assert summary_lines(r, vulnerable_count=3) == lines  # deterministic


def _seed(repo: Repo) -> int:
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(scan_id, Finding(
        probe_id="net.tls.kex_groups",
        algorithm="RSA-2048",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="server offers RSA-2048 key establishment",
    ))
    repo.finish_scan(scan_id, status="done")
    return scan_id


def test_report_context_includes_mosca_when_inputs_supplied(tmp_db_path) -> None:
    repo = Repo(tmp_db_path)
    repo.init_schema()
    scan_id = _seed(repo)
    inputs = MoscaInputs(data_lifetime_years=25, migration_years=5, threat_years=10)
    ctx = build_report_context(repo, scan_id, lang="en", mosca_inputs=inputs)
    assert "mosca" in ctx
    m = ctx["mosca"]
    assert m["at_risk"] is True
    assert m["gap_years"] == 20
    assert m["assumed"] is False
    assert m["vulnerable"] == 1          # one classical (red/yellow) finding
    assert "shelf-life gap" in m["summary"]


def test_report_context_mosca_defaults_when_absent(tmp_db_path) -> None:
    repo = Repo(tmp_db_path)
    repo.init_schema()
    ctx = build_report_context(repo, _seed(repo), lang="en")
    m = ctx["mosca"]
    assert m["assumed"] is True          # flagged as an assumption
    assert m["y"] == 5.0 and m["z"] == 10.0
