import pytest

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_ct_crtsh import NetCtCrtsh

_SAMPLE = [
    {"common_name": "example.com", "name_value": "example.com\nwww.example.com",
     "not_after": "2027-01-01T00:00:00"},
    {"common_name": "api.example.com", "name_value": "api.example.com",
     "not_after": "2020-01-01T00:00:00"},  # expired
    {"common_name": "*.example.com", "name_value": "*.example.com\nmail.example.com",
     "not_after": "2027-06-01T00:00:00"},
]


def _ctx(target: str | None) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(),
                       server_target=target)


async def _run(probe: NetCtCrtsh, ctx: ScanContext) -> list:
    found: list = []
    await probe.run(ctx, emit=lambda f: found.append(f))
    return found


@pytest.mark.asyncio
async def test_applies_only_for_domains():
    p = NetCtCrtsh(fetcher=lambda d: _SAMPLE)
    assert await p.applies(_ctx("example.com")) is True
    assert await p.applies(_ctx("example.com:443")) is True
    assert await p.applies(_ctx("192.168.1.1")) is False   # bare IP
    assert await p.applies(_ctx("localhost")) is False      # no dot
    assert await p.applies(_ctx(None)) is False


@pytest.mark.asyncio
async def test_emits_ct_inventory_with_subdomains_and_expiry():
    p = NetCtCrtsh(fetcher=lambda d: _SAMPLE)
    found = await _run(p, _ctx("example.com"))
    assert len(found) == 1
    f = found[0]
    assert f.classification is Classification.SEDERHANA
    assert f.evidence["certificate_count"] == 3
    assert f.evidence["expired_in_logs"] == 1
    # wildcard stripped, subdomains collected, apex excluded from subdomain list
    assert set(f.evidence["subdomains"]) == {"www.example.com", "api.example.com",
                                             "mail.example.com"}
    assert f.evidence["confidence"] == "medium"


@pytest.mark.asyncio
async def test_empty_or_failed_fetch_emits_nothing():
    assert await _run(NetCtCrtsh(fetcher=lambda d: []), _ctx("example.com")) == []

    def _boom(d):
        raise RuntimeError("crt.sh down")
    assert await _run(NetCtCrtsh(fetcher=_boom), _ctx("example.com")) == []


@pytest.mark.asyncio
async def test_no_target_emits_nothing():
    assert await _run(NetCtCrtsh(fetcher=lambda d: _SAMPLE), _ctx(None)) == []
