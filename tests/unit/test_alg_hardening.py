"""Coverage for the hardened classifier: new OIDs, PQC families, HNDL logic."""
from pqcscan.core.alg import (
    CNSA2_FULL_DEADLINE,
    CNSA2_HNDL_DEADLINE,
    classify,
    hndl_exposed,
    is_key_establishment,
    migration_deadline,
    normalise,
)
from pqcscan.core.types import Classification


def test_normalise_ml_dsa_nist_oid():
    assert normalise("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"


def test_normalise_slh_dsa_oid():
    assert normalise("2.16.840.1.101.3.4.3.20") == "SLH-DSA-SHA2-128s"


def test_normalise_ml_kem_oid():
    assert normalise("2.16.840.1.101.3.4.4.2") == "ML-KEM-768"


def test_normalise_kyber_alias():
    assert normalise("kyber768") == "ML-KEM-768"


def test_slh_dsa_is_pqc_ready():
    assert classify("SLH-DSA-SHA2-128s") == Classification.PQC_READY


def test_falcon_is_pqc_ready():
    assert classify("Falcon-512") == Classification.PQC_READY


def test_composite_hybrid_is_pqc_ready():
    assert classify("secp256r1_mlkem768") == Classification.PQC_READY


def test_rsa_pss_is_tinggi():
    assert classify("RSA-PSS") == Classification.TINGGI


def test_rsa_sha256_signame_is_tinggi_not_info():
    # Regression: a cert signed RSA-SHA256 must not fall through to INFO.
    assert classify("RSA-SHA256") == Classification.TINGGI


def test_ecdsa_p521_is_tinggi():
    assert classify("ECDSA-SHA512") == Classification.TINGGI


def test_ed448_is_tinggi():
    assert classify("Ed448") == Classification.TINGGI


def test_ffdhe2048_is_sangat_tinggi():
    assert classify("FFDHE-2048") == Classification.SANGAT_TINGGI


def test_aes128_gcm_is_sederhana():
    assert classify("AES-128-GCM") == Classification.SEDERHANA


def test_aes128_cbc_is_tinggi():
    assert classify("AES-128-CBC") == Classification.TINGGI


def test_tls13_suite_names_classified_by_strength():
    assert classify("TLS_AES_256_GCM_SHA384") == Classification.RENDAH
    assert classify("TLS_CHACHA20_POLY1305_SHA256") == Classification.RENDAH
    assert classify("TLS_AES_128_GCM_SHA256") == Classification.SEDERHANA


def test_chacha20_is_rendah():
    assert classify("ChaCha20-Poly1305") == Classification.RENDAH


def test_key_establishment_detection():
    assert is_key_establishment("ECDHE-RSA")
    assert is_key_establishment("RSA-2048")
    assert not is_key_establishment("ML-KEM-768")
    assert not is_key_establishment("ECDSA-SHA256")  # signature, not KEX


def test_hndl_only_for_key_establishment():
    assert hndl_exposed("RSA-2048")
    assert hndl_exposed("ECDHE")
    assert not hndl_exposed("ECDSA-SHA256")
    assert not hndl_exposed("ML-KEM-768")


def test_migration_deadline_hndl_earlier():
    assert migration_deadline("RSA-2048") == CNSA2_HNDL_DEADLINE
    assert migration_deadline("ECDSA-SHA256") == CNSA2_FULL_DEADLINE
    assert migration_deadline("ML-KEM-768") is None
    assert migration_deadline("AES-256-GCM") is None
