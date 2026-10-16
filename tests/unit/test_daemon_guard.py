"""Token auth + Origin (CSRF) guard on the daemon."""
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app, is_loopback


def test_is_loopback():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("10.0.0.5")
    assert not is_loopback("")                       # uvicorn: all interfaces
    assert not is_loopback("no-such-host.invalid")   # unresolvable → not trusted


def test_cross_origin_post_rejected_get_allowed(tmp_db_path, fast_registry):
    c = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry), base_url="http://127.0.0.1")
    r = c.post("/api/baselines", json={"scan_id": 1, "label": "x"},
               headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    assert c.get("/api/health", headers={"origin": "http://evil.example"}).status_code == 200
    same = c.post("/api/baselines", json={"scan_id": 1, "label": "x"},
                  headers={"origin": "http://127.0.0.1"})
    assert same.status_code == 404  # passed the guard, scan 1 doesn't exist


def test_dns_rebinding_host_rejected(tmp_db_path, fast_registry):
    c = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry,
                              allowed_hosts=["scanner.internal:8765"]), base_url="http://127.0.0.1")
    assert c.get("/api/health", headers={"host": "evil.example"}).status_code == 400
    # rebound Origin==Host no longer passes the CSRF check either
    r = c.post("/api/baselines", json={}, headers={"host": "evil.example", "origin": "http://evil.example"})
    assert r.status_code == 400
    for ok in ("127.0.0.1:8765", "localhost", "[::1]:8765", "scanner.internal", "SCANNER.INTERNAL:9"):
        assert c.get("/api/health", headers={"host": ok}).status_code == 200, ok


def test_token_required_when_configured(tmp_db_path, fast_registry):
    c = TestClient(create_app(db_path=tmp_db_path, registry=fast_registry, token="s3cret"), base_url="http://127.0.0.1")
    assert c.get("/api/health").status_code == 200           # probe endpoint stays open
    assert c.get("/api/scans").status_code == 401
    assert c.get("/api/scans", headers={"authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/scans", headers={"authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/", headers={"accept": "text/html"}, follow_redirects=False).status_code == 303
    assert c.get("/login").status_code == 200                # form, no token needed
    assert c.post("/login", data={"token": "nope"}).status_code == 401
    r = c.post("/login", data={"token": "s3cret"}, follow_redirects=False)
    cookie = r.headers.get("set-cookie", "")
    assert r.status_code == 303 and "pqcscan_session" in cookie and "s3cret" not in cookie
    assert c.get("/").status_code == 200                     # random session id, not the token


def test_render_slots_cap_exports(tmp_db_path, fast_registry):
    app = create_app(db_path=tmp_db_path, registry=fast_registry)
    c = TestClient(app, base_url="http://127.0.0.1")
    sid = app.state.repo.create_scan(mode="user", probe_versions={}, tool_versions={})
    app.state.repo.finish_scan(sid, status="done")
    assert c.get(f"/api/scans/{sid}/export/cbom").status_code == 200
    held = [app.state.render_slots.acquire(blocking=False) for _ in range(2)]
    assert all(held)
    assert c.get(f"/api/scans/{sid}/export/cbom").status_code == 429
    assert c.get(f"/scans/{sid}/report/tech").status_code == 429
    app.state.render_slots.release(); app.state.render_slots.release()
    assert c.get(f"/api/scans/{sid}/export/cbom").status_code == 200
