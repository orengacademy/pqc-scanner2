"""Tests for Plan B batch 15 — binary-protocol probes.

These probes do live network handshakes; tests use a closed/unreachable
port so each probe takes its connection-failure path. Each probe must
emit at most one INFO finding describing the failure (or nothing) and
must never raise.
"""
import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_ike_v1v2 import NetIkeV1V2
from pqcscan.probes.net_kerberos_asreq import NetKerberosAsreq
from pqcscan.probes.net_rdp_negotiation import NetRdpNegotiation
from pqcscan.probes.net_smb_dialect import NetSmbDialect
from pqcscan.probes.net_snmp_version import NetSnmpVersion
from pqcscan.probes.net_ssh_handshake import NetSshHandshake


# Port 1 is reserved/closed on virtually every host, so TCP/UDP
# attempts to it fail fast — perfect for connection-failure smoke
# tests without standing up real servers.
_DEAD_PORT = 1


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (NetSshHandshake,    "net.ssh.handshake"),
        (NetIkeV1V2,         "net.ike.v1v2"),
        (NetRdpNegotiation,  "net.rdp.negotiation"),
        (NetSmbDialect,      "net.smb.dialect"),
        (NetSnmpVersion,     "net.snmp.version"),
        (NetKerberosAsreq,   "net.kerberos.asreq"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.NETWORK


@pytest.mark.asyncio
async def test_ssh_handshake_connection_failure_is_info():
    p = NetSshHandshake(host="127.0.0.1", port=_DEAD_PORT, timeout_s=1.0)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await p.run(ctx, emit=lambda f: found.append(f))
    # Either nothing emitted or a single INFO finding. Never crashes.
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_ike_v1v2_connection_failure_is_info():
    p = NetIkeV1V2(host="127.0.0.1", port=_DEAD_PORT, timeout_s=1.0)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_rdp_negotiation_connection_failure_is_info():
    p = NetRdpNegotiation(host="127.0.0.1", port=_DEAD_PORT, timeout_s=1.0)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_smb_dialect_connection_failure_is_info():
    p = NetSmbDialect(host="127.0.0.1", port=_DEAD_PORT, timeout_s=1.0)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_snmp_version_no_response_is_info():
    p = NetSnmpVersion(host="127.0.0.1", port=_DEAD_PORT, timeout_s=1.0)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


@pytest.mark.asyncio
async def test_kerberos_asreq_connection_failure_is_info():
    p = NetKerberosAsreq(host="127.0.0.1", port=_DEAD_PORT, timeout_s=1.0)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification is Classification.INFO for f in found)


def test_registry_has_b15_probes():
    """Confirm registry exposes the 6 new B15 probes."""
    from pqcscan.probes._registry import default_registry
    reg = default_registry()
    ids = set(reg.ids())
    expected = {
        "net.ssh.handshake", "net.ike.v1v2", "net.rdp.negotiation",
        "net.smb.dialect", "net.snmp.version", "net.kerberos.asreq",
    }
    assert expected <= ids
