import time

import pytest
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app


@pytest.fixture
def client(tmp_db_path):
    app = create_app(db_path=tmp_db_path)
    return TestClient(app)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["version"]


def test_version(client):
    r = client.get("/api/version")
    assert r.status_code == 200
    assert r.json()["version"] == "0.1.0"


def test_post_scan_creates_and_runs(client):
    r = client.post("/api/scans")
    assert r.status_code == 202
    body = r.json()
    assert "id" in body
    scan_id = body["id"]

    s = None
    for _ in range(600):
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] == "done":
            break
        time.sleep(0.1)
    assert s is not None and s["status"] == "done"


def test_list_scans(client):
    client.post("/api/scans")
    r = client.get("/api/scans")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1
    assert "id" in data[0] and "status" in data[0]


def test_scan_findings(client):
    r = client.post("/api/scans")
    scan_id = r.json()["id"]
    for _ in range(600):
        if client.get(f"/api/scans/{scan_id}").json()["status"] == "done":
            break
        time.sleep(0.1)
    r = client.get(f"/api/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) >= 1
