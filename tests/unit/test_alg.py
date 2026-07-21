import pytest

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


@pytest.mark.parametrize("alg", [
    "MAYO-2", "SNOVA_24_5_4", "CROSSrsdp128small", "cross-rsdp-128-small",
    "HAWK-512", "SQIsign", "UOV-Ip",
])
def test_classify_onramp_signature_candidates_are_pqc_ready(alg):
    # NIST additional-signature on-ramp candidates shipped by oqs-provider.
    assert classify(alg) == Classification.PQC_READY


@pytest.mark.parametrize("alg", ["cross-signed-chain", "CROSS-SIGNED"])
def test_cross_signed_cert_terminology_is_not_pqc(alg):
    # Guard: the X.509 "cross-signed" relationship must not match CROSS the
    # PQC signature scheme (bare "CROSS" prefix would; the variant prefix won't).
    assert classify(alg) != Classification.PQC_READY


def test_classify_unknown_is_info():
    assert classify("totally-unknown-alg") == Classification.INFO


# --- Composite / hybrid ML-DSA signatures ------------------------------------
# LAMPS draft-ietf-lamps-pq-composite-sigs-19, IANA arc 1.3.6.1.5.5.7.6.{37..54}.
# A cert already migrated to hybrid PQC must classify PQC_READY, not INFO.
COMPOSITE_SIG_OIDS: list[tuple[str, str]] = [
    ("1.3.6.1.5.5.7.6.37", "ML-DSA-44+RSA2048-PSS"),
    ("1.3.6.1.5.5.7.6.38", "ML-DSA-44+RSA2048-PKCS15"),
    ("1.3.6.1.5.5.7.6.39", "ML-DSA-44+Ed25519"),
    ("1.3.6.1.5.5.7.6.40", "ML-DSA-44+ECDSA-P256"),
    ("1.3.6.1.5.5.7.6.41", "ML-DSA-65+RSA3072-PSS"),
    ("1.3.6.1.5.5.7.6.42", "ML-DSA-65+RSA3072-PKCS15"),
    ("1.3.6.1.5.5.7.6.43", "ML-DSA-65+RSA4096-PSS"),
    ("1.3.6.1.5.5.7.6.44", "ML-DSA-65+RSA4096-PKCS15"),
    ("1.3.6.1.5.5.7.6.45", "ML-DSA-65+ECDSA-P256"),
    ("1.3.6.1.5.5.7.6.46", "ML-DSA-65+ECDSA-P384"),
    ("1.3.6.1.5.5.7.6.47", "ML-DSA-65+ECDSA-brainpoolP256r1"),
    ("1.3.6.1.5.5.7.6.48", "ML-DSA-65+Ed25519"),
    ("1.3.6.1.5.5.7.6.49", "ML-DSA-87+ECDSA-P384"),
    ("1.3.6.1.5.5.7.6.50", "ML-DSA-87+ECDSA-brainpoolP384r1"),
    ("1.3.6.1.5.5.7.6.51", "ML-DSA-87+Ed448"),
    ("1.3.6.1.5.5.7.6.52", "ML-DSA-87+RSA3072-PSS"),
    ("1.3.6.1.5.5.7.6.53", "ML-DSA-87+RSA4096-PSS"),
    ("1.3.6.1.5.5.7.6.54", "ML-DSA-87+ECDSA-P521"),
]


@pytest.mark.parametrize(("oid", "name"), COMPOSITE_SIG_OIDS)
def test_composite_sig_oid_normalises_to_name(oid: str, name: str) -> None:
    assert normalise(oid) == name


@pytest.mark.parametrize(("oid", "name"), COMPOSITE_SIG_OIDS)
def test_composite_sig_oid_is_pqc_ready(oid: str, name: str) -> None:
    # A hybrid ML-DSA signature is quantum-safe — the PQC half holds.
    assert classify(oid) == Classification.PQC_READY


# --- Pure SLH-DSA (FIPS 205) — NIST CSOR 2.16.840.1.101.3.4.3.{20..31} --------
SLH_DSA_OIDS: list[tuple[str, str]] = [
    ("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"),
    ("2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f"),
    ("2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s"),
    ("2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f"),
    ("2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s"),
    ("2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f"),
    ("2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s"),
    ("2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f"),
    ("2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s"),
    ("2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f"),
    ("2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s"),
    ("2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"),
]


@pytest.mark.parametrize(("oid", "name"), SLH_DSA_OIDS)
def test_slh_dsa_oid_normalises_to_name(oid: str, name: str) -> None:
    assert normalise(oid) == name


@pytest.mark.parametrize(("oid", "name"), SLH_DSA_OIDS)
def test_slh_dsa_oid_is_pqc_ready(oid: str, name: str) -> None:
    assert classify(oid) == Classification.PQC_READY
