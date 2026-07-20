from pqcscan.core.remediation import enrich, suggest
from pqcscan.core.types import Classification, Finding, Severity


def _finding(alg, classif, remediation=None):
    return Finding(
        probe_id="net.tls.kex",
        algorithm=alg,
        classification=classif,
        severity=Severity.HIGH,
        title="t",
        remediation=remediation or {},
    )


def test_suggest_rsa_maps_to_ml_kem_with_hndl():
    d = suggest("RSA-2048", Classification.SANGAT_TINGGI)
    assert d["replacement"] == "ML-KEM-768"
    assert d["standard"] == "FIPS 203"
    assert d["hndl"] is True
    assert d["deadline"] == "2030-01-01"


def test_suggest_ecdsa_maps_to_ml_dsa_no_hndl():
    d = suggest("ECDSA-SHA256", Classification.TINGGI)
    assert d["replacement"] == "ML-DSA-65"
    assert d["standard"] == "FIPS 204"
    assert "hndl" not in d
    assert d["deadline"] == "2035-01-01"


def test_suggest_aes128_doubles_key():
    d = suggest("AES-128-GCM", Classification.SEDERHANA)
    assert d["replacement"] == "AES-256"


def test_suggest_pqc_ready_is_none():
    assert suggest("ML-KEM-768", Classification.PQC_READY) is None


def test_enrich_fills_replacement():
    f = _finding("RSA-2048", Classification.SANGAT_TINGGI)
    enrich(f)
    assert f.remediation["replacement"] == "ML-KEM-768"


def test_enrich_preserves_probe_snippet():
    f = _finding("ECDSA-SHA256", Classification.TINGGI, {"snippet": "do X"})
    enrich(f)
    assert f.remediation["snippet"] == "do X"
    assert f.remediation["replacement"] == "ML-DSA-65"


def test_enrich_does_not_override_probe_replacement():
    f = _finding("RSA-2048", Classification.SANGAT_TINGGI, {"replacement": "custom"})
    enrich(f)
    assert f.remediation["replacement"] == "custom"


def test_enrich_skips_pqc_ready():
    f = _finding("ML-KEM-768", Classification.PQC_READY)
    enrich(f)
    assert "replacement" not in f.remediation
