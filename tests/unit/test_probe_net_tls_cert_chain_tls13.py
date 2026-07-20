"""Tests for net.tls.cert_chain_tls13 (raw TLS 1.3 served-chain recovery).

The end-to-end recover_handshake test replays the RFC 8448 §3 exchange: the
published ClientHello record + client private key + (ServerHello record ||
encrypted server flight) must decrypt to the RFC's RSA leaf certificate."""

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from pqcscan.core.types import Classification
from pqcscan.probes._base import ScanContext
from pqcscan.probes.net_tls_cert_chain_tls13 import (
    NetTlsCertChainTls13,
    build_client_hello_tls13,
    extract_certificates_tls13,
    parse_server_hello_tls13,
    recover_handshake,
)


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


def _ctx(target: str | None = None) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(), server_target=target)


# --- RFC 8448 §3 wire bytes (verbatim) -----------------------------------
CLIENT_PRIVATE = _h("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")
CLIENT_HELLO_RECORD = _h(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
)
SERVER_HELLO_RECORD = _h(
    "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
)
ENCRYPTED_RECORD = _h(
    "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b"
)
SERVER_DATA = SERVER_HELLO_RECORD + ENCRYPTED_RECORD


def test_recover_handshake_decrypts_rfc8448_chain():
    priv = X25519PrivateKey.from_private_bytes(CLIENT_PRIVATE)
    result = recover_handshake(CLIENT_HELLO_RECORD, priv, SERVER_DATA)
    assert result is not None
    assert result["version"] == 0x0304
    assert result["cipher"] == 0x1301
    assert len(result["certs"]) == 1
    # rsa_pss_rsae_sha256 (0x0804) per the RFC CertificateVerify.
    assert result["cert_verify_scheme"] == 0x0804
    from cryptography import x509
    cert = x509.load_der_x509_certificate(result["certs"][0])
    assert cert.subject.rfc4514_string() == "CN=rsa"
    assert cert.signature_hash_algorithm is not None
    assert cert.signature_hash_algorithm.name == "sha256"


def test_recover_handshake_non_serverhello_is_none():
    priv = X25519PrivateKey.from_private_bytes(CLIENT_PRIVATE)
    # A lone alert record (0x15) carries no ServerHello.
    assert recover_handshake(CLIENT_HELLO_RECORD, priv, b"\x15\x03\x03\x00\x02\x02\x28") is None
    assert recover_handshake(CLIENT_HELLO_RECORD, priv, b"") is None


def test_parse_server_hello_extracts_keyshare_and_cipher():
    sh = parse_server_hello_tls13(SERVER_HELLO_RECORD[5:])
    assert sh is not None
    assert sh["cipher"] == 0x1301
    assert sh["version"] == 0x0304
    assert len(sh["server_pub"]) == 32


def test_extract_certificates_tls13_parses_entry_list():
    priv = X25519PrivateKey.from_private_bytes(CLIENT_PRIVATE)
    result = recover_handshake(CLIENT_HELLO_RECORD, priv, SERVER_DATA)
    assert result is not None
    # Re-parsing the recovered DER via a hand-built Certificate message body.
    der = result["certs"][0]
    body = (
        b"\x00"                                   # certificate_request_context: empty
        + (len(der) + 5).to_bytes(3, "big")       # certificate_list length
        + len(der).to_bytes(3, "big") + der       # entry cert_data
        + b"\x00\x00"                             # entry extensions: empty
    )
    certs = extract_certificates_tls13(body)
    assert certs == [der]


def test_build_client_hello_structure():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    ch = build_client_hello_tls13("example.com", pub)
    assert ch[0] == 0x16 and ch[5] == 0x01          # handshake record, ClientHello
    assert pub in ch                                 # our key_share is present
    assert b"\x00\x2b\x00\x03\x02\x03\x04" in ch     # supported_versions: TLS 1.3
    assert b"example.com" in ch                      # SNI


def test_resolve_target():
    p = NetTlsCertChainTls13()
    assert p._resolve_target(_ctx("host.example:8443")) == ("host.example", 8443)
    assert p._resolve_target(_ctx("host.example")) == ("host.example", 443)
    assert p._resolve_target(_ctx(None)) is None
    assert p._resolve_target(_ctx("host:notaport")) is None


@pytest.mark.asyncio
async def test_applies_requires_target():
    assert await NetTlsCertChainTls13(target="x:443").applies(_ctx()) is True
    assert await NetTlsCertChainTls13().applies(_ctx()) is False
    assert await NetTlsCertChainTls13().applies(_ctx("x:443")) is True


@pytest.mark.asyncio
async def test_run_on_unreachable_target_emits_nothing_and_does_not_raise():
    # Closed port: the handshake must fail cleanly with no findings, no raise.
    probe = NetTlsCertChainTls13(target="127.0.0.1:1", timeout=1.0)
    found: list = []
    await probe.run(_ctx(), emit=found.append)
    assert found == []


@pytest.mark.asyncio
async def test_run_emits_findings_from_recovered_chain(monkeypatch):
    probe = NetTlsCertChainTls13(target="srv:443")

    async def fake(host, port):
        priv = X25519PrivateKey.from_private_bytes(CLIENT_PRIVATE)
        return recover_handshake(CLIENT_HELLO_RECORD, priv, SERVER_DATA)

    monkeypatch.setattr(probe, "_handshake", fake)
    found: list = []
    await probe.run(_ctx(), emit=found.append)
    # One finding per cert (1) + one for CertificateVerify.
    assert len(found) == 2
    leaf = found[0]
    assert leaf.probe_id == "net.tls.cert_chain_tls13"
    assert leaf.algorithm.startswith("RSA")
    assert "served-chain leaf" in leaf.title
    verify = found[1]
    assert "CertificateVerify" in verify.title
    assert verify.classification is Classification.TINGGI  # RSA-PSS -> quantum-forgeable


@pytest.mark.asyncio
async def test_run_degrades_to_info_when_no_certs(monkeypatch):
    probe = NetTlsCertChainTls13(target="srv:443")

    async def fake(host, port):
        return {"version": 0x0304, "cipher": 0x1301, "certs": [], "cert_verify_scheme": None}

    monkeypatch.setattr(probe, "_handshake", fake)
    found: list = []
    await probe.run(_ctx(), emit=found.append)
    assert len(found) == 1
    assert found[0].classification is Classification.INFO
    assert "could not be decrypted" in found[0].title
