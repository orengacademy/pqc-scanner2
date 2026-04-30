"""Smoke tests for net.ports.tcp + net.db.{mongo,redis,postgres,mysql}_tls."""
import asyncio

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_db_mongo_tls import NetDbMongoTls
from pqcscan.probes.net_db_mysql_tls import NetDbMysqlTls
from pqcscan.probes.net_db_postgres_tls import NetDbPostgresTls
from pqcscan.probes.net_db_redis_tls import NetDbRedisTls
from pqcscan.probes.net_ports_tcp import NetPortsTcp


@pytest.mark.asyncio
async def test_ports_tcp_finds_an_open_port():
    """Bind a temporary listener on an OS-assigned port; probe should find it."""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    serving_task = asyncio.create_task(server.serve_forever())
    try:
        found: list = []
        probe = NetPortsTcp(host="127.0.0.1", ports=[port])
        ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
        await probe.run(ctx, emit=lambda f: found.append(f))
        assert len(found) == 1
        assert f"127.0.0.1:{port}" in found[0].title
    finally:
        server.close()
        await server.wait_closed()
        serving_task.cancel()


@pytest.mark.asyncio
async def test_ports_tcp_skips_closed_port():
    found: list = []
    probe = NetPortsTcp(host="127.0.0.1", ports=[1])  # port 1 always closed
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert found == []


@pytest.mark.parametrize(
    "cls,probe_id,default_port",
    [
        (NetDbPostgresTls, "net.db.postgres_tls", 5432),
        (NetDbMongoTls,    "net.db.mongo_tls",    27017),
        (NetDbRedisTls,    "net.db.redis_tls",    6379),
        (NetDbMysqlTls,    "net.db.mysql_tls",    3306),
    ],
)
def test_db_probe_metadata(cls, probe_id, default_port):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.NETWORK
    assert p.port == default_port


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [NetDbPostgresTls, NetDbMongoTls, NetDbRedisTls])
async def test_db_probe_connection_failure_emits_info(cls):
    found: list = []
    probe = cls(host="127.0.0.1", port=1, verify=False)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.INFO


@pytest.mark.asyncio
async def test_mysql_emits_deferral_notice():
    found: list = []
    probe = NetDbMysqlTls()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert "not yet implemented" in found[0].title.lower()
