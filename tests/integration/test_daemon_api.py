import time

import pytest
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app


@pytest.fixture
def client(tmp_db_path, fast_registry):
    app = create_app(db_path=tmp_db_path, registry=fast_registry)
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
    for _ in range(3000):
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
    for _ in range(3000):
        if client.get(f"/api/scans/{scan_id}").json()["status"] == "done":
            break
        time.sleep(0.1)
    r = client.get(f"/api/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) >= 1


def _wait_for_done(client, scan_id):
    for _ in range(3000):
        if client.get(f"/api/scans/{scan_id}").json()["status"] == "done":
            return
        time.sleep(0.1)
    raise AssertionError(f"scan {scan_id} did not finish")


def test_post_baseline_creates_row(client):
    sid = client.post("/api/scans").json()["id"]
    _wait_for_done(client, sid)
    r = client.post(
        "/api/baselines",
        json={"scan_id": sid, "label": "Q2 baseline", "notes": "audit"},
    )
    assert r.status_code == 201
    bid = r.json()["id"]
    assert isinstance(bid, int) and bid > 0

    rows = client.get("/api/baselines").json()
    assert any(b["id"] == bid and b["label"] == "Q2 baseline" for b in rows)


def test_post_baseline_400_for_invalid(client):
    r = client.post("/api/baselines", json={"label": "missing scan_id"})
    assert r.status_code == 400
    r = client.post("/api/baselines", json={"scan_id": 1, "label": ""})
    assert r.status_code == 400


def test_diff_endpoint(client):
    sid = client.post("/api/scans").json()["id"]
    _wait_for_done(client, sid)
    # Diffing a scan against itself should yield zero changes and many common.
    r = client.get(f"/api/scans/{sid}/diff", params={"baseline_scan": sid})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == [] and body["removed"] == []
    assert body["common"] >= 1


def test_diff_404_for_missing_scan(client):
    r = client.get("/api/scans/9999/diff", params={"baseline_scan": 1})
    assert r.status_code == 404
