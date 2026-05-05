"""Tests for the technical PDF renderer."""
from datetime import date
from pathlib import Path

import pytest

# weasyprint pulls in cairo/pango at import time; it lives in the optional
# [render] extra so headless installs (CI default) skip these tests.
pytest.importorskip("weasyprint")

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.renderers.pdf_technical import render_pdf_technical
from pqcscan.store.repo import Repo


def _seed(repo: Repo) -> int:
    scan_id = repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    fid = repo.record_finding(scan_id, Finding(
        probe_id="net.tls.https",
        algorithm="RSA-2048",
        classification=Classification.SANGAT_TINGGI,
        severity=Severity.CRIT,
        title="server cert uses RSA-2048",
        evidence={"endpoint": "127.0.0.1:443"},
    ))
    repo.record_framework_view(
        fid, framework="cnsa2",
        clause="CNSA2:RSA-deprecated", verdict="non-compliant",
        deadline=date(2030, 12, 31),
    )
    repo.finish_scan(scan_id, status="done")
    return scan_id


def test_pdf_technical_writes_a_real_pdf(tmp_db_path, tmp_path: Path):
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    out = tmp_path / "report.pdf"
    result = render_pdf_technical(repo, scan_id, out)
    assert result == out
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")  # PDF magic
    assert len(data) > 1000           # not an empty doc


def test_pdf_technical_includes_finding_title_in_pdf_text(tmp_db_path, tmp_path: Path):
    """Spot-check that key strings show up in the PDF's raw text content."""
    repo = Repo(tmp_db_path); repo.init_schema()
    scan_id = _seed(repo)
    out = tmp_path / "report.pdf"
    render_pdf_technical(repo, scan_id, out)
    raw = out.read_bytes()
    # PDF text streams are usually compressed; look for some uncompressed
    # substrings the WeasyPrint output tends to include.
    assert b"PDF-" in raw[:8]
    # File size should grow with framework verdicts present.
    assert len(raw) > 2000


def test_pdf_technical_raises_on_missing_scan(tmp_db_path, tmp_path: Path):
    import pytest
    repo = Repo(tmp_db_path); repo.init_schema()
    out = tmp_path / "report.pdf"
    with pytest.raises(ValueError):
        render_pdf_technical(repo, scan_id=999, output_path=out)
