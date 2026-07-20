"""The HTML reports must render rich, correct content in English AND Bahasa
Melayu. These use the HTML path (no weasyprint), so they run everywhere."""
from datetime import date

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.renderers._report_context import build_report_context
from pqcscan.renderers.pdf_executive import build_html_executive
from pqcscan.renderers.pdf_technical import build_html_technical
from pqcscan.store.repo import Repo


def _seed(repo: Repo) -> int:
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    fid = repo.record_finding(scan_id, Finding(
        probe_id="net.tls.kex_groups",
        algorithm="RSA-2048",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="server offers RSA-2048 key establishment",
        evidence={"endpoint": "127.0.0.1:443"},
        remediation={"replacement": "ML-KEM-768", "standard": "FIPS 203",
                     "deadline": "2030-01-01", "hndl": True},
    ))
    repo.record_framework_view(
        fid, framework="cnsa2", clause="CNSA2:RSA-deprecated",
        verdict="non-compliant", deadline=date(2030, 12, 31),
    )
    repo.record_finding(scan_id, Finding(
        probe_id="host.openssl.version",
        algorithm="ML-KEM-768",
        classification=Classification.PQC_READY,
        severity=Severity.INFO,
        title="OpenSSL supports ML-KEM",
    ))
    repo.finish_scan(scan_id, status="done")
    return scan_id


def test_context_builds_priority_groups(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    ctx = build_report_context(repo, scan_id, lang="en")
    assert ctx["readiness"] is not None
    assert ctx["hndl_count"] == 1
    groups = ctx["priority"]
    assert groups and groups[0]["target"] == "ML-KEM-768"
    assert groups[0]["hndl"] is True
    assert groups[0]["count"] == 1


def test_technical_report_english(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    html = build_html_technical(repo, _seed(repo), lang="en")
    assert 'lang="en"' in html
    assert "Executive summary" in html
    assert "Readiness score" in html
    assert "Priority remediation" in html
    assert "ML-KEM-768" in html
    assert "HNDL" in html


def test_technical_report_bahasa(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    html = build_html_technical(repo, _seed(repo), lang="ms")
    assert 'lang="ms"' in html
    assert "Ringkasan eksekutif" in html      # Executive summary
    assert "Skor kesediaan" in html           # Readiness score
    assert "Pembaikan keutamaan" in html      # Priority remediation
    assert "Executive summary" not in html    # no English leakage in headings


def test_executive_report_both_languages(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    en = build_html_executive(repo, scan_id, lang="en")
    ms = build_html_executive(repo, scan_id, lang="ms")
    assert "Executive Summary" in en
    assert "Ringkasan Eksekutif" in ms
    # Both carry the readiness gauge + priority target.
    assert "ML-KEM-768" in en and "ML-KEM-768" in ms


def test_report_lang_falls_back_to_english(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    html = build_html_technical(repo, _seed(repo), lang="zz")
    assert "Executive summary" in html  # unknown locale → English
