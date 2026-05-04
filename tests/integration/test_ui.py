import pytest
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app


@pytest.fixture
def client(tmp_db_path):
    return TestClient(create_app(db_path=tmp_db_path))


def test_dashboard_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "pqcscan" in r.text.lower()
    assert "scan now" in r.text.lower()


def test_scans_list_page(client):
    r = client.get("/scans")
    assert r.status_code == 200
    assert "<table" in r.text


def test_static_htmx_served(client):
    r = client.get("/static/htmx-1.9.10.min.js")
    assert r.status_code == 200
    assert "htmx" in r.text.lower()


def test_scan_detail_page_404_for_missing(client):
    r = client.get("/scans/999")
    assert r.status_code == 404


def test_frameworks_list_page(client):
    r = client.get("/frameworks")
    assert r.status_code == 200
    # All 10 bundled frameworks (YAML 'framework:' slug) should be linked.
    for slug in (
        "bukukerja", "nist-ir-8547", "nist-sp-800-227", "cnsa2",
        "bsi-tr-02102-1", "anssi-pqc", "mas-notice-655", "enisa-pqc",
        "mykripto", "nacsa-arahan-ke-9",
    ):
        assert slug in r.text


def test_framework_detail_page(client):
    r = client.get("/frameworks/bukukerja")
    assert r.status_code == 200
    assert "BUKUKERJA" in r.text
    assert "non-compliant" in r.text


def test_framework_detail_404(client):
    r = client.get("/frameworks/does-not-exist")
    assert r.status_code == 404


def test_probes_list_page(client):
    r = client.get("/probes")
    assert r.status_code == 200
    assert "host.openssl.config" in r.text
    assert "net.tls.https" in r.text
    assert "fs.cert.x509" in r.text


def test_nav_includes_new_pages(client):
    r = client.get("/")
    assert 'href="/frameworks"' in r.text
    assert 'href="/probes"' in r.text
