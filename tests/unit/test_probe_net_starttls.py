"""Smoke tests for net.starttls.{smtp,imap,pop3,ftp,ldap}."""
import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_starttls_ftp import NetStarttlsFtp
from pqcscan.probes.net_starttls_imap import NetStarttlsImap
from pqcscan.probes.net_starttls_ldap import NetStarttlsLdap
from pqcscan.probes.net_starttls_pop3 import NetStarttlsPop3
from pqcscan.probes.net_starttls_smtp import NetStarttlsSmtp


@pytest.mark.parametrize(
    "cls,probe_id,default_port",
    [
        (NetStarttlsSmtp, "net.starttls.smtp", 25),
        (NetStarttlsImap, "net.starttls.imap", 143),
        (NetStarttlsPop3, "net.starttls.pop3", 110),
        (NetStarttlsFtp,  "net.starttls.ftp",  21),
        (NetStarttlsLdap, "net.starttls.ldap", 389),
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
    [NetStarttlsSmtp, NetStarttlsImap, NetStarttlsPop3, NetStarttlsFtp],
)
async def test_text_starttls_connection_failure_emits_info(cls):
    """Port 1 is always closed → helper reports a connection failure as INFO."""
    found: list = []
    p = cls(host="127.0.0.1", port=1, verify=False)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert "STARTTLS" in found[0].title


@pytest.mark.asyncio
async def test_ldap_emits_deferral_notice():
    """LDAP STARTTLS is a v0.2.0+ probe; v0.1.0 emits an INFO-level deferral."""
    found: list = []
    p = NetStarttlsLdap()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert "not yet implemented" in found[0].title.lower() or \
           "deferred" in (found[0].evidence.get("deferred_to") or "").lower()
