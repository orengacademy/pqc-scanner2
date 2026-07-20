"""QRAMM framework YAML must load and evaluate the expected verdicts."""
from pqcscan.compliance.engine import ComplianceEngine
from pqcscan.core.types import Classification, Finding, Severity


def _f(alg, classif=Classification.TINGGI):
    return Finding(
        probe_id="net.tls.kex",
        algorithm=alg,
        classification=classif,
        severity=Severity.HIGH,
        title=alg,
    )


def _verdicts(alg, classif=Classification.TINGGI):
    engine = ComplianceEngine()
    return [
        v for v in engine.evaluate(_f(alg, classif))
        if v.framework == "qramm"
    ]


def test_qramm_loaded():
    engine = ComplianceEngine()
    frameworks = {v.framework for v in engine.evaluate(_f("RSA-2048"))}
    assert "qramm" in frameworks


def test_qramm_rsa_undersized_non_compliant():
    verdicts = _verdicts("RSA-2048", Classification.SANGAT_TINGGI)
    assert any(v.verdict == "non-compliant" for v in verdicts)


def test_qramm_rsa_hndl_deadline_2030():
    verdicts = _verdicts("RSA-4096")
    at_risk = [v for v in verdicts if v.verdict == "at-risk"]
    assert any(str(v.deadline) == "2030-01-01" for v in at_risk)


def test_qramm_mlkem_compliant():
    verdicts = _verdicts("ML-KEM-768", Classification.PQC_READY)
    assert verdicts and all(v.verdict == "compliant" for v in verdicts)


def test_qramm_aes256_compliant():
    verdicts = _verdicts("AES-256-GCM", Classification.RENDAH)
    assert any(v.verdict == "compliant" for v in verdicts)
