"""Tests for Repo.create_baseline / list_baselines / diff_findings (E2)."""
from datetime import datetime

import pytest

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.store.repo import Repo


def _mkfinding(probe_id: str, algorithm: str, title: str) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm=algorithm,
        classification=Classification.TINGGI,
        severity=Severity.HIGH,
        title=title,
        evidence={},
        remediation={},
        created_at=datetime.utcnow(),
    )


@pytest.fixture
def repo(tmp_db_path):
    r = Repo(tmp_db_path)
    r.init_schema()
    return r


def test_create_and_list_baseline(repo):
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    bid = repo.create_baseline(scan_id=sid, label="2026-Q2 baseline",
                               notes="locked for audit")
    assert bid > 0
    rows = repo.list_baselines()
    assert len(rows) == 1
    assert rows[0].label == "2026-Q2 baseline"
    assert rows[0].scan_id == sid
    assert rows[0].notes == "locked for audit"


def test_create_baseline_rejects_missing_scan(repo):
    with pytest.raises(ValueError, match="scan 999 not found"):
        repo.create_baseline(scan_id=999, label="bogus")


def test_diff_findings_added_removed_common(repo):
    base_sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    cur_sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    # Baseline has X, Y, Z.
    repo.record_finding(base_sid, _mkfinding("p1", "RSA-2048", "host A: RSA-2048 in /etc/ssl"))
    repo.record_finding(base_sid, _mkfinding("p1", "RSA-2048", "host B: RSA-2048 in /etc/ssl"))
    repo.record_finding(base_sid, _mkfinding("p2", "SHA1",     "git tag X signed with SHA1"))
    # Current has Y, Z, W. (X removed; W added; Y, Z common.)
    repo.record_finding(cur_sid,  _mkfinding("p1", "RSA-2048", "host B: RSA-2048 in /etc/ssl"))
    repo.record_finding(cur_sid,  _mkfinding("p2", "SHA1",     "git tag X signed with SHA1"))
    repo.record_finding(cur_sid,  _mkfinding("p3", "MD5",      "user upload: MD5 hash"))
    diff = repo.diff_findings(current_scan_id=cur_sid, baseline_scan_id=base_sid)
    assert len(diff["added"]) == 1
    assert diff["added"][0].title == "user upload: MD5 hash"
    assert len(diff["removed"]) == 1
    assert diff["removed"][0].title == "host A: RSA-2048 in /etc/ssl"
    assert diff["common"] == 2


def test_diff_identical_scans_yields_no_changes(repo):
    sid = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    repo.record_finding(sid, _mkfinding("p1", "RSA-2048", "x"))
    diff = repo.diff_findings(current_scan_id=sid, baseline_scan_id=sid)
    assert diff["added"] == [] and diff["removed"] == [] and diff["common"] == 1


def test_get_baseline_returns_none_for_missing(repo):
    assert repo.get_baseline(999) is None
