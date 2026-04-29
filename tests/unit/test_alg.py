from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification


def test_normalise_oid():
    assert normalise("1.2.840.113549.1.1.11") == "RSA-SHA256"


def test_normalise_friendly_name():
    assert normalise("sha256WithRSAEncryption") == "RSA-SHA256"


def test_normalise_lib_name():
    assert normalise("RSA-SHA256") == "RSA-SHA256"


def test_normalise_unknown_passthrough():
    assert normalise("some-weird-alg") == "SOME-WEIRD-ALG"


def test_classify_rsa_2048_is_sangat_tinggi():
    # Per spec Appendix B: RSA <3072 -> Sangat Tinggi.
    assert classify("RSA-2048") == Classification.SANGAT_TINGGI


def test_classify_rsa_3072_is_tinggi():
    # Boundary: 3072 is the line; >= 3072 -> Tinggi.
    assert classify("RSA-3072") == Classification.TINGGI


def test_classify_rsa_1024_is_sangat_tinggi():
    assert classify("RSA-1024") == Classification.SANGAT_TINGGI


def test_classify_md5_is_sangat_tinggi():
    assert classify("MD5") == Classification.SANGAT_TINGGI


def test_classify_aes_256_gcm_is_rendah():
    assert classify("AES-256-GCM") == Classification.RENDAH


def test_classify_ml_kem_768_is_pqc_ready():
    assert classify("ML-KEM-768") == Classification.PQC_READY


def test_classify_hybrid_is_pqc_ready():
    assert classify("X25519MLKEM768") == Classification.PQC_READY


def test_classify_unknown_is_info():
    assert classify("totally-unknown-alg") == Classification.INFO
