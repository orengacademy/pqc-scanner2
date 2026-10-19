"""net.tls.pqc_handshake — openssl s_client output handling (subprocess stubbed)."""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pqcscan.core.types import Classification
from pqcscan.probes import net_tls_pqc_handshake as mod
from pqcscan.probes._base import ScanContext


class _Proc:
    def __init__(self, out: bytes) -> None:
        self._out = out

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return self._out, b""


async def _run(monkeypatch: pytest.MonkeyPatch, out: bytes) -> tuple[list, list]:
    calls: list = []

    async def fake_exec(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(args)
        return _Proc(out)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    found: list = []
    ctx = ScanContext(scan_id=0, mode="user", available_capabilities=set(), server_target="127.0.0.1:8443")
    await mod.NetTlsPqcHandshake().run(ctx, found.append)
    return found, calls


def test_default_groups_omit_codepoints_openssl_35_rejects() -> None:
    assert "X25519Kyber768Draft00" not in mod._DEFAULT_HYBRID_GROUPS
    assert mod._DEFAULT_HYBRID_GROUPS[0] == "X25519MLKEM768"


_OPENSSL30_REJECT = b"Call to SSL_CONF_cmd(-groups, X25519MLKEM768:X25519) failed\n"


def _raw(monkeypatch: pytest.MonkeyPatch, result: dict | None) -> None:
    async def fake_select(host: str, port: int, io_timeout: float) -> dict | None:
        return result

    monkeypatch.setattr(mod, "select_group", fake_select)


@pytest.mark.asyncio
async def test_rejected_group_list_and_no_raw_answer_is_local_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    _raw(monkeypatch, None)
    found, _ = await _run(monkeypatch, _OPENSSL30_REJECT)
    assert [f.title for f in found] == ["local openssl does not support PQC hybrid groups"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("group", "expected"), [
    ("x25519", Classification.TINGGI),
    ("X25519MLKEM768", Classification.PQC_READY),
])
async def test_rejected_group_list_falls_back_to_raw_client_hello(
    monkeypatch: pytest.MonkeyPatch, group: str, expected: Classification,
) -> None:
    # OpenSSL 3.0 cannot offer the hybrid groups; the raw hello offers them for it.
    _raw(monkeypatch, {"version": 0x0304, "cipher": 0x1301, "group_code": 0, "group_name": group,
                       "is_pqc": expected is Classification.PQC_READY})
    found, _ = await _run(monkeypatch, _OPENSSL30_REJECT)
    assert [(f.algorithm, f.classification) for f in found] == [(group, expected)]
    assert found[0].evidence["method"].startswith("raw ClientHello")


@pytest.mark.asyncio
async def test_classical_fallback_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    found, calls = await _run(monkeypatch, b"Protocol  : TLSv1.3\nNegotiated TLS1.3 group: X25519\n")
    assert [(f.algorithm, f.classification) for f in found] == [("X25519", Classification.TINGGI)]
    assert "127.0.0.1:8443" in calls[0]


@pytest.mark.asyncio
async def test_hybrid_group_is_pqc_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    found, _ = await _run(monkeypatch, b"Negotiated TLS1.3 group: X25519MLKEM768\n")
    assert [(f.algorithm, f.classification) for f in found] == [("X25519MLKEM768", Classification.PQC_READY)]


@pytest.mark.asyncio
async def test_openssl_32_plus_peer_temp_key_wording(monkeypatch: pytest.MonkeyPatch) -> None:
    # OpenSSL >= 3.2 prints "Peer Temp Key" for a classical group (was "Server Temp Key").
    found, _ = await _run(monkeypatch, b"Peer Temp Key: X25519, 253 bits\nProtocol: TLSv1.3\n")
    assert [(f.algorithm, f.classification) for f in found] == [("X25519", Classification.TINGGI)]


# --- end to end: real loopback servers, s_client stubbed to fail like OpenSSL 3.0 ---


@contextlib.contextmanager
def _tls13_server(tmp_path: Path, group: str | None):  # type: ignore[no-untyped-def]
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "kex.test")])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    if group:
        ctx.set_ecdh_curve(group)
    srv = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        with contextlib.suppress(OSError):
            conn, _ = srv.accept()
            with contextlib.suppress(OSError), conn, ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield srv.getsockname()[1]
    finally:
        srv.close()


async def _run_against(monkeypatch: pytest.MonkeyPatch, port: int) -> list:
    async def fake_exec(*args, **kwargs):  # type: ignore[no-untyped-def]
        return _Proc(_OPENSSL30_REJECT)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    found: list = []
    ctx = ScanContext(scan_id=0, mode="user", available_capabilities=set(), server_target=f"127.0.0.1:{port}")
    await mod.NetTlsPqcHandshake(timeout_s=5).run(ctx, found.append)
    return found


@pytest.mark.asyncio
async def test_classical_x25519_server_flagged_without_local_hybrid_support(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    with _tls13_server(tmp_path, "X25519") as port:
        found = await _run_against(monkeypatch, port)
    assert [(f.algorithm.lower(), f.classification) for f in found] == [("x25519", Classification.TINGGI)]


@pytest.mark.asyncio
@pytest.mark.skipif(ssl.OPENSSL_VERSION_INFO < (3, 5), reason="serving X25519MLKEM768 needs OpenSSL >= 3.5")
async def test_hybrid_server_not_flagged_without_local_hybrid_support(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    with _tls13_server(tmp_path, None) as port:  # OpenSSL 3.5 default: X25519MLKEM768 first
        found = await _run_against(monkeypatch, port)
    assert [(f.algorithm, f.classification) for f in found] == [("X25519MLKEM768", Classification.PQC_READY)]
