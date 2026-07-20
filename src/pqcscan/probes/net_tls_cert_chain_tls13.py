"""net.tls.cert_chain_tls13 — served certificate chain + sig algs over TLS 1.3.

The roadmap's hardest deferred item. In TLS 1.2 the Certificate handshake
message is cleartext (net.tls.cert_chain reads it directly), but TLS 1.3
*encrypts* EncryptedExtensions / Certificate / CertificateVerify under the
handshake traffic keys. To recover the served chain this probe therefore does a
real TLS 1.3 key exchange over a raw socket (no OS ssl):

  1. Offer an X25519 key_share + supported_versions(TLS 1.3) + broad
     signature_algorithms in a ClientHello.
  2. Read the ServerHello, compute the X25519 shared secret, and run the
     RFC 8446 §7.1 key schedule (see _tls13_keyschedule) to derive the server
     handshake traffic key/iv.
  3. AEAD-decrypt the server's encrypted flight, parse the Certificate message
     (one finding per cert: key alg + signature alg via `classify`) and the
     CertificateVerify SignatureScheme.

The whole network path is wrapped so a socket error / timeout / unexpected TLS
never escapes run(): on clean failure it emits nothing, and if the handshake
completes far enough to negotiate a cipher but the chain can't be recovered it
degrades to a single INFO reporting the negotiated version/cipher.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._tls13_keyschedule import (
    CIPHER_SUITES,
    aead_open,
    handshake_traffic_keys,
)

_FIXED_RANDOM = bytes(range(32))
# Broad TLS 1.3 signature_algorithms so any RSA/ECDSA/EdDSA server replies.
_SIG_ALGS = [
    0x0403, 0x0503, 0x0603,          # ecdsa_secp{256,384,521}
    0x0804, 0x0805, 0x0806,          # rsa_pss_rsae_sha{256,384,512}
    0x0809, 0x080A, 0x080B,          # rsa_pss_pss_sha{256,384,512}
    0x0401, 0x0501, 0x0601,          # rsa_pkcs1_sha{256,384,512}
    0x0807, 0x0808,                  # ed25519, ed448
]

# CertificateVerify SignatureScheme -> (pretty name, classify-able alg name)
_SCHEMES: dict[int, tuple[str, str]] = {
    0x0401: ("rsa_pkcs1_sha256", "RSA-SHA256"),
    0x0501: ("rsa_pkcs1_sha384", "RSA-SHA384"),
    0x0601: ("rsa_pkcs1_sha512", "RSA-SHA512"),
    0x0403: ("ecdsa_secp256r1_sha256", "ECDSA-SHA256"),
    0x0503: ("ecdsa_secp384r1_sha384", "ECDSA-SHA384"),
    0x0603: ("ecdsa_secp521r1_sha512", "ECDSA-SHA512"),
    0x0804: ("rsa_pss_rsae_sha256", "RSA-PSS"),
    0x0805: ("rsa_pss_rsae_sha384", "RSA-PSS"),
    0x0806: ("rsa_pss_rsae_sha512", "RSA-PSS"),
    0x0809: ("rsa_pss_pss_sha256", "RSA-PSS"),
    0x080A: ("rsa_pss_pss_sha384", "RSA-PSS"),
    0x080B: ("rsa_pss_pss_sha512", "RSA-PSS"),
    0x0807: ("ed25519", "Ed25519"),
    0x0808: ("ed448", "Ed448"),
    0x0201: ("rsa_pkcs1_sha1", "RSA-SHA1"),
    0x0203: ("ecdsa_sha1", "ECDSA-SHA1"),
}


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _vec16(body: bytes) -> bytes:
    return _u16(len(body)) + body


def _ext(t: int, body: bytes) -> bytes:
    return _u16(t) + _vec16(body)


def build_client_hello_tls13(
    server_name: str | None, public_key: bytes, *, random: bytes = _FIXED_RANDOM
) -> bytes:
    """Build a TLS record carrying a TLS 1.3 ClientHello offering an X25519
    key_share (`public_key`) plus a broad signature_algorithms list."""
    key_share = _u16(0x001D) + _vec16(public_key)                 # entry: x25519 || key
    sigalgs = b"".join(_u16(s) for s in _SIG_ALGS)
    exts = b"".join([
        _ext(0x002B, b"\x02\x03\x04"),                           # supported_versions: TLS 1.3
        _ext(0x000A, _vec16(_u16(0x001D))),                       # supported_groups: x25519
        _ext(0x0033, _vec16(key_share)),                          # key_share: client x25519 share
        _ext(0x000D, _vec16(sigalgs)),                            # signature_algorithms
    ])
    if server_name:
        host = server_name.encode("idna") if server_name.isascii() else server_name.encode()
        exts += _ext(0x0000, _vec16(b"\x00" + _vec16(host)))      # server_name
    body = (
        b"\x03\x03" + random + b"\x00"                            # version + random + session_id
        + _vec16(b"\x13\x01\x13\x02\x13\x03")                     # cipher_suites
        + b"\x01\x00"                                             # compression: null
        + _vec16(exts)
    )
    handshake = b"\x01" + _u24(len(body)) + body
    return b"\x16\x03\x01" + _vec16(handshake)


def _split_records(data: bytes) -> list[tuple[int, bytes]]:
    """Split a byte stream into (content_type, whole_record_with_header)."""
    out: list[tuple[int, bytes]] = []
    off = 0
    while off + 5 <= len(data):
        ctype = data[off]
        rec_len = struct.unpack(">H", data[off + 3:off + 5])[0]
        if off + 5 + rec_len > len(data):
            break
        out.append((ctype, data[off:off + 5 + rec_len]))
        off += 5 + rec_len
    return out


def _handshake_message(record: bytes) -> bytes:
    """Return a single-record handshake message payload (record minus header)."""
    return record[5:]


def parse_server_hello_tls13(hs: bytes) -> dict | None:
    """Parse a ServerHello handshake message (starts with type byte 0x02).

    Returns {version, cipher, server_pub} or None if not a usable ServerHello
    with a TLS 1.3 X25519 key_share.
    """
    if len(hs) < 4 or hs[0] != 0x02:
        return None
    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + hs_len]
    try:
        off = 2 + 32                                             # legacy_version + random
        sid_len = body[off]
        off += 1 + sid_len
        cipher = struct.unpack(">H", body[off:off + 2])[0]
        off += 2 + 1                                             # cipher + compression
        ext_total = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        exts = body[off:off + ext_total]
    except IndexError:
        return None

    version = 0x0303
    server_pub: bytes | None = None
    i = 0
    while i + 4 <= len(exts):
        et = struct.unpack(">H", exts[i:i + 2])[0]
        el = struct.unpack(">H", exts[i + 2:i + 4])[0]
        ev = exts[i + 4:i + 4 + el]
        i += 4 + el
        if et == 0x002B and len(ev) >= 2:                       # supported_versions (selected)
            version = struct.unpack(">H", ev[:2])[0]
        elif et == 0x0033 and len(ev) >= 4:                     # key_share (selected)
            group = struct.unpack(">H", ev[:2])[0]
            klen = struct.unpack(">H", ev[2:4])[0]
            if group == 0x001D:
                server_pub = ev[4:4 + klen]
    if server_pub is None or cipher not in CIPHER_SUITES:
        return None
    return {"version": version, "cipher": cipher, "server_pub": server_pub}


def _reassemble(payload: bytes) -> list[tuple[int, bytes]]:
    """Split concatenated handshake messages into (msg_type, body)."""
    out: list[tuple[int, bytes]] = []
    off = 0
    while off + 4 <= len(payload):
        mtype = payload[off]
        mlen = int.from_bytes(payload[off + 1:off + 4], "big")
        body = payload[off + 4:off + 4 + mlen]
        if len(body) < mlen:
            break
        out.append((mtype, body))
        off += 4 + mlen
    return out


def extract_certificates_tls13(cert_msg_body: bytes) -> list[bytes]:
    """Parse a TLS 1.3 Certificate message body into DER certificates.

    struct { opaque certificate_request_context<0..255>;
             CertificateEntry certificate_list<0..2^24-1>; }
    CertificateEntry { opaque cert_data<1..2^24-1>; Extension exts<0..2^16-1>; }
    """
    if not cert_msg_body:
        return []
    ctx_len = cert_msg_body[0]
    p = 1 + ctx_len
    if p + 3 > len(cert_msg_body):
        return []
    list_len = int.from_bytes(cert_msg_body[p:p + 3], "big")
    p += 3
    end = min(p + list_len, len(cert_msg_body))
    certs: list[bytes] = []
    while p + 3 <= end:
        clen = int.from_bytes(cert_msg_body[p:p + 3], "big")
        p += 3
        cert = cert_msg_body[p:p + clen]
        p += clen
        if len(cert) == clen and cert:
            certs.append(cert)
        if p + 2 > end:
            break
        ext_len = struct.unpack(">H", cert_msg_body[p:p + 2])[0]
        p += 2 + ext_len
    return certs


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


def recover_handshake(
    client_hello_record: bytes, client_private: X25519PrivateKey, server_data: bytes
) -> dict | None:
    """Decrypt a TLS 1.3 server flight and recover its Certificate chain.

    Pure function of its inputs (no I/O), so it is testable against RFC 8448.
    Returns {version, cipher, certs:[DER], cert_verify_scheme} or None if the
    ServerHello / key exchange can't be recovered. `certs` may be empty if the
    handshake was decrypted but no Certificate message was present.
    """
    records = _split_records(server_data)
    # First handshake record carries the ServerHello.
    sh_record = next((rec for ctype, rec in records if ctype == 0x16), None)
    if sh_record is None:
        return None
    sh = parse_server_hello_tls13(_handshake_message(sh_record))
    if sh is None:
        return None

    try:
        shared = client_private.exchange(X25519PublicKey.from_public_bytes(sh["server_pub"]))
    except Exception:
        return None

    client_hello_msg = _handshake_message(client_hello_record)
    server_hello_msg = _handshake_message(sh_record)
    keys = handshake_traffic_keys(shared, client_hello_msg + server_hello_msg, sh["cipher"])

    plaintext = bytearray()
    seq = 0
    for ctype, rec in records:
        if ctype in (0x16, 0x14):                               # ServerHello / dummy CCS
            continue
        if ctype != 0x17:                                       # only application_data is encrypted
            continue
        opened = aead_open(
            keys.server_key, keys.server_iv, seq, rec, is_chacha=keys.is_chacha
        )
        seq += 1
        if opened is not None:
            plaintext += opened

    certs: list[bytes] = []
    scheme: int | None = None
    for mtype, body in _reassemble(bytes(plaintext)):
        if mtype == 0x0B:                                        # Certificate
            certs = extract_certificates_tls13(body)
        elif mtype == 0x0F and len(body) >= 2:                  # CertificateVerify
            scheme = struct.unpack(">H", body[:2])[0]
    return {
        "version": sh["version"],
        "cipher": sh["cipher"],
        "certs": certs,
        "cert_verify_scheme": scheme,
    }


class NetTlsCertChainTls13(Probe):
    """Recover a TLS 1.3 server's served certificate chain + per-cert sig algs."""

    id = "net.tls.cert_chain_tls13"
    family = ProbeFamily.NETWORK
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "cnsa2:tls")

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
        try:
            result = await self._handshake(host, port)
        except Exception:
            return
        if result is None:
            return

        certs = result["certs"]
        if not certs:
            # Degrade gracefully: we negotiated a session but couldn't recover
            # the chain (unsupported cipher, HRR, fragmented flight, ...).
            emit(Finding(
                probe_id=self.id,
                algorithm="TLS1.3",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=(f"{host}:{port} negotiated TLS 1.3 "
                       f"(cipher 0x{result['cipher']:04x}) but served chain "
                       f"could not be decrypted"),
                evidence={
                    "host": host, "port": port,
                    "tls_version": f"0x{result['version']:04x}",
                    "cipher": f"0x{result['cipher']:04x}",
                },
            ))
            return

        for depth, der in enumerate(certs):
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
                title=(f"{host}:{port} TLS 1.3 served-chain {role} cert: "
                       f"{key_alg} signed with {sig or 'unknown'}"),
                evidence={
                    "host": host, "port": port, "depth": depth, "role": role,
                    "subject": cert.subject.rfc4514_string(),
                    "key_algorithm": key_alg, "signature_hash": sig,
                    "tls_version": f"0x{result['version']:04x}",
                    "cipher": f"0x{result['cipher']:04x}",
                },
            ))

        scheme = result["cert_verify_scheme"]
        if scheme is not None:
            pretty, alg = _SCHEMES.get(scheme, (f"unknown-0x{scheme:04x}", ""))
            cls = classify(alg) if alg else Classification.INFO
            emit(Finding(
                probe_id=self.id,
                algorithm=normalise(alg) if alg else pretty,
                classification=cls,
                severity=_sev(cls),
                title=(f"{host}:{port} TLS 1.3 CertificateVerify signed with "
                       f"{pretty}"),
                evidence={
                    "host": host, "port": port,
                    "signature_scheme": pretty,
                    "scheme_code": f"0x{scheme:04x}",
                },
            ))

    async def _handshake(self, host: str, port: int) -> dict | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except (OSError, TimeoutError):
            return None
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        client_hello = build_client_hello_tls13(host, public)
        try:
            writer.write(client_hello)
            await writer.drain()
            buf = bytearray()
            while len(buf) < 262144:
                try:
                    chunk = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
                except (OSError, TimeoutError):
                    break
                if not chunk:
                    break
                buf += chunk
                result = recover_handshake(client_hello, private, bytes(buf))
                if result is not None and result["certs"]:
                    return result
            return recover_handshake(client_hello, private, bytes(buf))
        except (OSError, TimeoutError):
            return None
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await writer.wait_closed()
