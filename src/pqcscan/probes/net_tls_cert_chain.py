"""net.tls.cert_chain — served certificate chain + signature algorithms (TLS 1.2).

The OS-ssl probes only see the LEAF cert; this reads the FULL served chain and
each cert's signature algorithm over a raw TLS 1.2 handshake (no OS ssl). In
TLS 1.2 the Certificate handshake message is sent in CLEARTEXT, so the chain is
readable without completing the key exchange. (TLS 1.3 encrypts it — out of
scope here; net.tls.kex_groups covers the TLS 1.3 KEX side.)
"""
from __future__ import annotations

import asyncio
import contextlib
import struct

from cryptography import x509

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_FIXED_RANDOM = bytes(range(32))
# TLS 1.2 ECDHE/RSA + ECDHE/ECDSA + RSA cipher suites — broad enough that any
# RSA- or ECDSA-certificate server replies with a Certificate message.
_CIPHERS = [
    0xC02B, 0xC02C, 0xC02F, 0xC030, 0x009C, 0x009D, 0xC013, 0xC014, 0x002F, 0x0035,
]


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _vec16(body: bytes) -> bytes:
    return _u16(len(body)) + body


def _ext(t: int, body: bytes) -> bytes:
    return _u16(t) + _vec16(body)


def build_client_hello_tls12(server_name: str | None = None, *, random: bytes = _FIXED_RANDOM) -> bytes:
    """Build a TLS record carrying a TLS 1.2 ClientHello (no supported_versions,
    so the server negotiates <= TLS 1.2 and sends a cleartext Certificate)."""
    groups = _ext(0x000A, _vec16(_u16(0x001D) + _u16(0x0017) + _u16(0x0018)))   # x25519/secp256r1/secp384r1
    ec_pts = _ext(0x000B, b"\x01\x00")                                          # ec_point_formats: uncompressed
    sigalgs = _ext(0x000D, _vec16(
        _u16(0x0403) + _u16(0x0804) + _u16(0x0401) + _u16(0x0503) + _u16(0x0805) + _u16(0x0601)
    ))
    exts = groups + ec_pts + sigalgs
    if server_name:
        host = server_name.encode("idna") if server_name.isascii() else server_name.encode()
        exts += _ext(0x0000, _vec16(b"\x00" + _vec16(host)))

    suites = b"".join(_u16(c) for c in _CIPHERS)
    body = (
        b"\x03\x03" + random + b"\x00"
        + _vec16(suites) + b"\x01\x00"
        + _vec16(exts)
    )
    handshake = b"\x01" + _u24(len(body)) + body
    return b"\x16\x03\x01" + _vec16(handshake)


def reassemble_handshake(data: bytes) -> bytes:
    """Concatenate the payloads of all TLS handshake records (0x16) in `data`,
    so a handshake message split across records is rejoined."""
    out = bytearray()
    off = 0
    while off + 5 <= len(data):
        rec_type = data[off]
        rec_len = struct.unpack(">H", data[off + 3:off + 5])[0]
        payload = data[off + 5:off + 5 + rec_len]
        if rec_type == 0x16:
            out += payload
        off += 5 + rec_len
    return bytes(out)


def extract_certificates(data: bytes) -> list[bytes]:
    """Pull the DER certificates out of the TLS 1.2 Certificate handshake
    message in a server response. Returns [] if none found."""
    hs = reassemble_handshake(data)
    off = 0
    while off + 4 <= len(hs):
        msg_type = hs[off]
        msg_len = int.from_bytes(hs[off + 1:off + 4], "big")
        body = hs[off + 4:off + 4 + msg_len]
        off += 4 + msg_len
        if msg_type != 0x0B:                       # Certificate
            continue
        if len(body) < 3:
            return []
        certs: list[bytes] = []
        list_len = int.from_bytes(body[0:3], "big")
        p = 3
        end = 3 + list_len
        while p + 3 <= end and p + 3 <= len(body):
            clen = int.from_bytes(body[p:p + 3], "big")
            p += 3
            cert = body[p:p + clen]
            p += clen
            if len(cert) == clen and cert:
                certs.append(cert)
        return certs
    return []


def _key_algorithm(pk: object) -> str:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    if isinstance(pk, rsa.RSAPublicKey):
        return f"RSA-{pk.key_size}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pk.curve.name}"
    if isinstance(pk, dsa.DSAPublicKey):
        return f"DSA-{pk.key_size}"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pk).__name__


def _sig_hash(cert: x509.Certificate) -> str | None:
    try:
        h = cert.signature_hash_algorithm
    except Exception:
        return None
    return h.name.upper() if h else None


def _worst(a: Classification, b: Classification) -> Classification:
    order = {
        Classification.PQC_READY: 0, Classification.INFO: 1, Classification.ERROR: 1,
        Classification.RENDAH: 2, Classification.SEDERHANA: 3,
        Classification.TINGGI: 4, Classification.SANGAT_TINGGI: 5,
    }
    return a if order[a] >= order[b] else b


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]


class NetTlsCertChain(Probe):
    """Read a TLS 1.2 server's served certificate chain + per-cert sig algs."""

    id = "net.tls.cert_chain"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, target: str | None = None, timeout: float = 6.0):
        self.target = target
        self.timeout = timeout

    def _resolve_target(self, ctx: ScanContext) -> tuple[str, int] | None:
        raw = self.target or ctx.server_target
        if not raw:
            return None
        host, _, port = raw.partition(":")
        if not host:
            return None
        if not port:
            return host, 443
        try:
            return host, int(port)
        except ValueError:
            return None

    async def applies(self, ctx: ScanContext) -> bool:
        return self._resolve_target(ctx) is not None

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        tgt = self._resolve_target(ctx)
        if tgt is None:
            return
        host, port = tgt
        raw = await self._fetch(host, port)
        if not raw:
            return
        for depth, der in enumerate(extract_certificates(raw)):
            try:
                cert = x509.load_der_x509_certificate(der)
            except (ValueError, TypeError):
                continue
            key_alg = _key_algorithm(cert.public_key())
            sig = _sig_hash(cert)
            cls = _worst(classify(key_alg), classify(sig) if sig else Classification.INFO)
            role = "leaf" if depth == 0 else "intermediate/root"
            emit(Finding(
                probe_id=self.id,
                algorithm=normalise(key_alg),
                classification=cls,
                severity=_sev(cls),
                title=f"{host}:{port} served-chain {role} cert: {key_alg} signed with {sig or 'unknown'}",
                evidence={
                    "host": host, "port": port, "depth": depth, "role": role,
                    "subject": cert.subject.rfc4514_string(),
                    "key_algorithm": key_alg, "signature_hash": sig,
                },
            ))

    async def _fetch(self, host: str, port: int) -> bytes:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except (OSError, TimeoutError):
            return b""
        try:
            writer.write(build_client_hello_tls12(host))
            await writer.drain()
            # The Certificate message can span several records; read until the
            # peer pauses (ServerHelloDone) or the buffer is large enough.
            buf = bytearray()
            while len(buf) < 65536:
                try:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)
                except (OSError, TimeoutError):
                    break
                if not chunk:
                    break
                buf += chunk
                if extract_certificates(bytes(buf)):
                    break
            return bytes(buf)
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await writer.wait_closed()
