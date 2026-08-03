import asyncio
import struct

from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_db_mssql_tls import (
    ENCRYPT_NOT_SUP,
    ENCRYPT_OFF,
    ENCRYPT_ON,
    ENCRYPT_REQ,
    NetDbMssqlTls,
    build_prelogin,
    parse_prelogin_response,
    unwrap_tds,
    wrap_tds,
)


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(
        scan_id=1, mode="user", available_capabilities=set(),
        scan_paths=[], server_target=target, ot_targets=[], sniff=None,
    )


# ---------------------------------------------------------------- pure parts

def test_build_prelogin_is_a_wellformed_tds_packet():
    pkt = build_prelogin()
    assert pkt[0] == 0x12                       # TDS PRELOGIN packet type
    assert pkt[1] == 0x01                       # status: end of message
    assert struct.unpack(">H", pkt[2:4])[0] == len(pkt)
    payload = pkt[8:]
    assert 0xFF in payload                      # option-list terminator
    # The ENCRYPTION option must be offered as ENCRYPT_ON so the server
    # reveals its own stance in the reply.
    parsed = parse_prelogin_response(payload)
    assert parsed is not None and parsed["encryption"] == ENCRYPT_ON


def test_wrap_unwrap_tds_roundtrip():
    payload = b"\x16\x03\x01\x00\x05hello"
    assert unwrap_tds(wrap_tds(payload)) == payload


def test_unwrap_tds_rejects_garbage():
    assert unwrap_tds(b"") is None
    assert unwrap_tds(b"\x12\x01\x00") is None          # truncated header
    assert unwrap_tds(b"\x12\x01\xff\xff\x00\x00\x01\x00") is None  # bad length


def _prelogin_response(encryption: int) -> bytes:
    # Option table is 11 bytes (two 5-byte entries + 1-byte terminator);
    # offsets are absolute from the start of the PRELOGIN payload.
    options = (
        bytes([0x00]) + struct.pack(">HH", 11, 6)
        + bytes([0x01]) + struct.pack(">HH", 17, 1)
        + bytes([0xFF])
    )
    return options + b"\x10\x00\x0b\xe2\x00\x00" + bytes([encryption])


def test_parse_prelogin_response_reads_encryption_stance():
    for stance in (ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ):
        parsed = parse_prelogin_response(_prelogin_response(stance))
        assert parsed is not None and parsed["encryption"] == stance


def test_parse_prelogin_response_never_raises_on_garbage():
    assert parse_prelogin_response(b"") is None
    assert parse_prelogin_response(b"\xff") is None
    assert parse_prelogin_response(b"\x01\xff\xff\xff\xff\xff") is None


# ------------------------------------------------------------- target logic

def test_default_target_is_localhost_1433():
    assert NetDbMssqlTls()._resolve_target(_ctx()) == ("127.0.0.1", 1433)


def test_ctx_server_target_host_is_used_with_tds_port():
    # --target's port belongs to the primary TLS service; TDS keeps 1433.
    assert NetDbMssqlTls()._resolve_target(_ctx("db.example.com:443")) == (
        "db.example.com", 1433,
    )


def test_explicit_constructor_target_wins():
    probe = NetDbMssqlTls(host="10.0.0.9", port=14330)
    assert probe._resolve_target(_ctx("other:1")) == ("10.0.0.9", 14330)


# ---------------------------------------------------- behaviour, fake server

def _server_hello_selecting(group: int) -> bytes:
    """Minimal TLS 1.3 HelloRetryRequest-style ServerHello whose key_share
    extension names `group` as the server's selected group."""
    exts = (
        struct.pack(">HH", 0x002B, 2) + b"\x03\x04"
        + struct.pack(">HH", 0x0033, 2) + struct.pack(">H", group)
    )
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"
        + struct.pack(">H", 0x1301) + b"\x00"
        + struct.pack(">H", len(exts)) + exts
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


async def _fake_mssql(replies: list[bytes]):
    """One-shot fake TDS server: for each client packet, send the next reply."""
    queue = list(replies)

    async def handler(reader, writer):
        try:
            while queue:
                header = await reader.readexactly(8)
                length = struct.unpack(">H", header[2:4])[0]
                await reader.readexactly(length - 8)
                writer.write(queue.pop(0))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _run_probe(port: int) -> list:
    findings = []
    await NetDbMssqlTls(host="127.0.0.1", port=port).run(_ctx(), findings.append)
    return findings


async def test_plaintext_only_server_is_sangat_tinggi():
    server, port = await _fake_mssql([wrap_tds(_prelogin_response(ENCRYPT_NOT_SUP))])
    async with server:
        findings = await _run_probe(port)
    assert any(
        f.classification.value == "sangat-tinggi" and f.algorithm == "PLAINTEXT"
        for f in findings
    )


async def test_optional_encryption_is_tinggi():
    server, port = await _fake_mssql([wrap_tds(_prelogin_response(ENCRYPT_OFF))])
    async with server:
        findings = await _run_probe(port)
    assert any(f.classification.value == "tinggi" for f in findings)


async def test_pqc_hybrid_group_is_pqc_ready():
    server, port = await _fake_mssql([
        wrap_tds(_prelogin_response(ENCRYPT_REQ)),
        wrap_tds(_server_hello_selecting(0x11EC)),      # X25519MLKEM768
    ])
    async with server:
        findings = await _run_probe(port)
    assert any(
        f.classification.value == "pqc-ready" and "X25519MLKEM768" in f.title
        for f in findings
    )


async def test_classical_group_is_sederhana_with_hndl():
    server, port = await _fake_mssql([
        wrap_tds(_prelogin_response(ENCRYPT_REQ)),
        wrap_tds(_server_hello_selecting(0x001D)),      # x25519
    ])
    async with server:
        findings = await _run_probe(port)
    hits = [f for f in findings if f.classification.value == "sederhana"]
    assert hits and hits[0].evidence.get("group") == "x25519"


async def test_unreachable_server_yields_info_not_crash():
    findings = []
    await NetDbMssqlTls(host="127.0.0.1", port=1).run(_ctx(), findings.append)
    assert findings and findings[0].classification.value == "info"


def test_registered_in_default_registry():
    from pqcscan.probes._registry import default_registry
    assert "net.db.mssql_tls" in default_registry().ids()
