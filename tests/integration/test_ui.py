import pytest
from fastapi.testclient import TestClient

from pqcscan.daemon.app import create_app


@pytest.fixture
def client(tmp_db_path, fast_registry):
    return TestClient(create_app(db_path=tmp_db_path, registry=fast_registry))


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
    assert 'href="/baselines"' in r.text
    assert 'href="/probes"' in r.text


def test_baselines_page_empty(client):
    r = client.get("/baselines")
    assert r.status_code == 200
    assert "Baselines" in r.text
    assert "No baselines yet" in r.text


def test_baselines_diff_page_404_for_missing(client):
    r = client.get("/baselines/diff", params={"scan": 1, "baseline_scan": 2})
    assert r.status_code == 404


def test_baselines_diff_page_after_creating_baseline(client):
    sid = client.post("/api/scans").json()["id"]
    # Wait for scan to finish so findings exist.
    import time
    for _ in range(3000):
        if client.get(f"/api/scans/{sid}").json()["status"] == "done":
            break
        time.sleep(0.1)
    bid = client.post(
        "/api/baselines", json={"scan_id": sid, "label": "test"},
    ).json()["id"]
    assert bid > 0
    r = client.get(
        "/baselines/diff", params={"scan": sid, "baseline_scan": sid},
    )
    assert r.status_code == 200
    assert "Diff:" in r.text
    assert "0 added" in r.text and "0 removed" in r.text


def test_default_locale_renders_english(client):
    r = client.get("/baselines")
    assert r.status_code == 200
    assert "Baselines" in r.text
    assert 'lang="en"' in r.text


def test_locale_cookie_renders_bahasa(client):
    r = client.get("/baselines", cookies={"pqcscan_locale": "ms"})
    assert r.status_code == 200
    assert "Garis Dasar" in r.text          # MS title
    assert "Baselines" not in r.text         # EN title gone
    assert 'lang="ms"' in r.text


def test_set_locale_endpoint_sets_cookie(client):
    r = client.post("/i18n/ms", follow_redirects=False)
    assert r.status_code == 303
    assert r.cookies.get("pqcscan_locale") == "ms"
    # Subsequent request without explicit cookie picks up the set one.
    r2 = client.get("/")
    assert "Papan Pemuka" in r2.text


def test_set_locale_rejects_unknown(client):
    r = client.post("/i18n/fr", follow_redirects=False)
    assert r.status_code == 400


def test_settings_page(client):
    r = client.get("/settings")
    assert r.status_code == 200
    assert "Settings" in r.text
    # Version, python, platform, mode, db, capabilities, probes, frameworks
    # rows must render with their labels.
    for label in ("Version", "Python", "Platform", "Privilege mode",
                  "Database", "Capabilities", "Probes registered",
                  "Frameworks bundled"):
        assert label in r.text
    assert "0.1.0" in r.text       # __version__
    assert "sqlite" in r.text       # db_url


def test_settings_page_in_bahasa(client):
    r = client.get("/settings", cookies={"pqcscan_locale": "ms"})
    assert r.status_code == 200
    assert "Tetapan" in r.text       # MS title
    assert "Pangkalan data" in r.text  # MS db label


def test_create_baseline_form_redirects(client):
    sid = client.post("/api/scans").json()["id"]
    import time
    for _ in range(3000):
        if client.get(f"/api/scans/{sid}").json()["status"] == "done":
            break
        time.sleep(0.1)
    r = client.post(
        "/baselines/create",
        data={"scan_id": str(sid), "label": "form-baseline"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/baselines"
    # The baseline is queryable on the API.
    rows = client.get("/api/baselines").json()
    assert any(b["label"] == "form-baseline" for b in rows)


def test_create_baseline_form_404_for_missing_scan(client):
    r = client.post(
        "/baselines/create",
        data={"scan_id": "999", "label": "x"},
        follow_redirects=False,
    )
    assert r.status_code == 404


def test_scan_detail_shows_mark_baseline_form(client):
    sid = client.post("/api/scans").json()["id"]
    import time
    for _ in range(3000):
        if client.get(f"/api/scans/{sid}").json()["status"] == "done":
            break
        time.sleep(0.1)
    r = client.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert "/baselines/create" in r.text
    assert 'name="scan_id"' in r.text
    assert f'value="{sid}"' in r.text
