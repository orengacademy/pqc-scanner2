"""RFC 8448 §3 ("Simple 1-RTT Handshake") test vectors for the TLS 1.3 key
schedule. All hex below is copied verbatim from RFC 8448; reproducing these
exact bytes proves the schedule + AEAD are correct without a live server."""

from pqcscan.probes._tls13_keyschedule import (
    aead_open,
    derive_secret,
    handshake_traffic_keys,
    hkdf_expand_label,
    hkdf_extract,
    transcript_hash,
)


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


# --- RFC 8448 §3 inputs / expected outputs -------------------------------
CLIENT_HELLO = _h(
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
)
SERVER_HELLO = _h(
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
)
SHARED_SECRET = _h("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
EARLY_SECRET = _h("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
TRANSCRIPT_HASH = _h("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
HANDSHAKE_SECRET = _h("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
SERVER_HS_SECRET = _h("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
CLIENT_HS_SECRET = _h("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
SERVER_KEY = _h("3fce516009c21727d0f2e4e86ee403bc")
SERVER_IV = _h("5d313eb2671276ee13000b30")

CIPHER_TLS_AES_128_GCM_SHA256 = 0x1301


def test_transcript_hash_matches_rfc():
    assert transcript_hash(CLIENT_HELLO + SERVER_HELLO) == TRANSCRIPT_HASH


def test_early_secret_extract():
    # Early Secret = HKDF-Extract(salt=0, IKM=0).
    assert hkdf_extract(b"", b"\x00" * 32) == EARLY_SECRET


def test_handshake_traffic_keys_reproduce_rfc8448():
    keys = handshake_traffic_keys(
        SHARED_SECRET, CLIENT_HELLO + SERVER_HELLO, CIPHER_TLS_AES_128_GCM_SHA256
    )
    assert keys.handshake_secret == HANDSHAKE_SECRET
    assert keys.server_hs_secret == SERVER_HS_SECRET
    assert keys.client_hs_secret == CLIENT_HS_SECRET
    assert keys.server_key == SERVER_KEY
    assert keys.server_iv == SERVER_IV
    assert keys.hash_name == "sha256"
    assert keys.key_len == 16
    assert keys.is_chacha is False


def test_derive_secret_and_expand_label_primitives():
    # Derive-Secret(handshake_secret, "s hs traffic", TranscriptHash) == server hs secret.
    assert derive_secret(HANDSHAKE_SECRET, "s hs traffic", TRANSCRIPT_HASH) == SERVER_HS_SECRET
    # HKDF-Expand-Label(server_hs, "key", "", 16) == server write key.
    assert hkdf_expand_label(SERVER_HS_SECRET, "key", b"", 16) == SERVER_KEY
    assert hkdf_expand_label(SERVER_HS_SECRET, "iv", b"", 12) == SERVER_IV


# --- full AEAD decrypt of the server's encrypted flight ------------------
ENCRYPTED_RECORD = _h(
    "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40a"
    "a40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389"
    "280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c790207"
    "16cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b"
    "3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd6"
    "10928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab"
    "66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a"
    "56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a26"
    "4ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637"
    "ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a8"
    "4dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87"
    "c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89f"
    "c50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c"
    "6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca"
    "01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c"
    "0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84"
    "5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd"
    "4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b"
)


def test_aead_open_decrypts_server_flight():
    keys = handshake_traffic_keys(
        SHARED_SECRET, CLIENT_HELLO + SERVER_HELLO, CIPHER_TLS_AES_128_GCM_SHA256
    )
    plain = aead_open(
        keys.server_key, keys.server_iv, 0, ENCRYPTED_RECORD, is_chacha=keys.is_chacha
    )
    assert plain is not None
    # First decrypted handshake message is EncryptedExtensions (type 0x08).
    assert plain[0] == 0x08
    # The flight contains a Certificate (0x0b) and CertificateVerify (0x0f).
    assert b"\x0b\x00\x01\xb9" in plain          # Certificate header (445-octet msg)
    assert b"\x0f\x00\x00\x84" in plain          # CertificateVerify header


def test_aead_open_wrong_seq_fails_auth():
    keys = handshake_traffic_keys(
        SHARED_SECRET, CLIENT_HELLO + SERVER_HELLO, CIPHER_TLS_AES_128_GCM_SHA256
    )
    # Wrong sequence number -> wrong nonce -> AEAD auth failure -> None.
    assert aead_open(
        keys.server_key, keys.server_iv, 1, ENCRYPTED_RECORD, is_chacha=keys.is_chacha
    ) is None
