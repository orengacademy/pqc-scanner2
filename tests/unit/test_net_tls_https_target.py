import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_tls_https import NetTlsHttps


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        scan_paths=[], server_target=target, ot_targets=[], sniff=None,
    )


def test_default_is_localhost_443():
    assert NetTlsHttps()._resolve_target(_ctx()) == ("127.0.0.1", 443)


def test_ctx_server_target_is_honoured():
    assert NetTlsHttps()._resolve_target(_ctx("example.com:8443")) == ("example.com", 8443)


def test_ctx_server_target_defaults_to_443():
    assert NetTlsHttps()._resolve_target(_ctx("example.com")) == ("example.com", 443)


def test_explicit_constructor_host_wins_over_ctx():
    probe = NetTlsHttps(host="10.0.0.5", port=8443)
    assert probe._resolve_target(_ctx("example.com:1234")) == ("10.0.0.5", 8443)


@pytest.mark.asyncio
async def test_run_connects_to_resolved_target(monkeypatch):
    seen = {}

    async def fake_probe(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr("pqcscan.probes.net_tls_https.run_tls_probe", fake_probe)
    await NetTlsHttps().run(_ctx("example.com:8443"), lambda f: None)
    assert seen["host"] == "example.com"
    assert seen["port"] == 8443
