"""Smoke tests for net.tls.{imaps,pop3s,smtps,ldaps,mqtts}.

The deep TLS-server fixture lives in test_probe_net_tls_https.py; here we just
verify class metadata, default ports, and that connection failure to a closed
port emits an INFO finding (proving the helper is wired correctly).
"""
import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_tls_imaps import NetTlsImaps
from pqcscan.probes.net_tls_ldaps import NetTlsLdaps
from pqcscan.probes.net_tls_mqtts import NetTlsMqtts
from pqcscan.probes.net_tls_pop3s import NetTlsPop3s
from pqcscan.probes.net_tls_smtps import NetTlsSmtps


@pytest.mark.parametrize(
    "cls,probe_id,default_port",
    [
        (NetTlsImaps, "net.tls.imaps", 993),
        (NetTlsPop3s, "net.tls.pop3s", 995),
        (NetTlsSmtps, "net.tls.smtps", 465),
        (NetTlsLdaps, "net.tls.ldaps", 636),
        (NetTlsMqtts, "net.tls.mqtts", 8883),
    ],
)
def test_metadata(cls, probe_id, default_port):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.NETWORK
    assert p.port == default_port


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls",
    [NetTlsImaps, NetTlsPop3s, NetTlsSmtps, NetTlsLdaps, NetTlsMqtts],
)
async def test_connection_failure_emits_info(cls):
    # Port 1 is reserved/never-listening on Linux; expect a connect refusal.
    found: list = []
    p = cls(host="127.0.0.1", port=1, verify=False)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert "TLS connection failed" in found[0].title
