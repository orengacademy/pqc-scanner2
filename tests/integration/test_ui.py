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
