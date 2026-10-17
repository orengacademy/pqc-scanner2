"""net.tls.pqc_handshake — openssl s_client output handling (subprocess stubbed)."""
from __future__ import annotations

import asyncio

import pytest

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


@pytest.mark.asyncio
async def test_rejected_group_list_is_reported_as_local_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    found, _ = await _run(monkeypatch, b"Call to SSL_CONF_cmd(-groups, X25519MLKEM768:X25519) failed\n")
    assert [f.title for f in found] == ["local openssl does not support PQC hybrid groups"]


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
