"""Tests for the compliance engine + 3 framework YAMLs."""
from datetime import date

import pytest

from pqcscan.compliance.engine import ComplianceEngine, FrameworkRules, _Rule
from pqcscan.core.types import Classification, Finding, Severity


@pytest.fixture
def engine():
    """Engine that auto-loads bukukerja/nist-ir-8547/cnsa2 YAMLs."""
    return ComplianceEngine()


def _f(alg: str, classification: Classification = Classification.TINGGI,
       severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        probe_id="t.test",
        algorithm=alg,
        classification=classification,
        severity=severity,
        title=f"finding for {alg}",
    )


def test_engine_loads_all_ten_frameworks(engine):
    names = {fw.framework for fw in engine.frameworks}
    expected = {
        "bukukerja", "nist-ir-8547", "nist-sp-800-227", "cnsa2",
        "bsi-tr-02102-1", "anssi-pqc", "mas-notice-655", "enisa-pqc",
        "mykripto", "nacsa-arahan-ke-9",
    }
    assert expected.issubset(names)


def test_mykripto_phase_clauses_fire_on_classification(engine):
    f = _f("RSA-2048", classification=Classification.TINGGI, severity=Severity.HIGH)
    verdicts = list(engine.evaluate(f))
    mykripto = [v for v in verdicts if v.framework == "mykripto"]
    assert any(v.clause == "MYKRIPTO:phase-2/migrate-by-2030" for v in mykripto)


def test_anssi_2030_deadline_attached_to_rsa(engine):
    f = _f("RSA-3072", classification=Classification.TINGGI, severity=Severity.HIGH)
    verdicts = list(engine.evaluate(f))
    anssi = [v for v in verdicts if v.framework == "anssi-pqc"
             and v.clause == "ANSSI-PQC:RSA-hybrid-required"]
    assert anssi and anssi[0].deadline == date(2030, 12, 31)


def test_mas_655_disallows_legacy_ciphers(engine):
    f = _f("3DES", classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT)
    verdicts = list(engine.evaluate(f))
    mas = [v for v in verdicts if v.framework == "mas-notice-655"]
    assert any(v.clause == "MAS-655:cipher-disallowed" and v.verdict == "non-compliant"
               for v in mas)


def test_bukukerja_maps_classifications(engine):
    f = _f("RSA-2048", classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT)
    verdicts = list(engine.evaluate(f))
    bukukerja_verdicts = [v for v in verdicts if v.framework == "bukukerja"]
    assert any(
        v.clause == "BUKUKERJA:risk-register/sangat-tinggi"
        and v.verdict == "non-compliant"
        for v in bukukerja_verdicts
    )


def test_nist_flags_rsa_lt_2048_as_disallowed(engine):
    f = _f("RSA-1024", classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT)
    verdicts = list(engine.evaluate(f))
    nist = [v for v in verdicts if v.framework == "nist-ir-8547"]
    assert any(v.clause == "NIST-IR-8547:RSA-disallowed" and v.verdict == "non-compliant"
               for v in nist)


def test_nist_flags_rsa_2048_as_at_risk_with_2030_deadline(engine):
    f = _f("RSA-2048", classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT)
    verdicts = list(engine.evaluate(f))
    nist = [v for v in verdicts if v.framework == "nist-ir-8547"]
    deprecated = [v for v in nist if v.clause == "NIST-IR-8547:RSA-deprecated-2030"]
    assert deprecated and deprecated[0].verdict == "at-risk"
    assert deprecated[0].deadline == date(2030, 12, 31)


def test_cnsa2_marks_aes_128_non_compliant(engine):
    f = _f("AES-128-GCM", classification=Classification.SEDERHANA, severity=Severity.MED)
    verdicts = list(engine.evaluate(f))
    cnsa = [v for v in verdicts if v.framework == "cnsa2"]
    assert any(v.clause == "CNSA2:AES-128-deprecated" and v.verdict == "non-compliant"
               for v in cnsa)


def test_ml_kem_768_compliant_in_all_frameworks(engine):
    f = _f("ML-KEM-768", classification=Classification.PQC_READY, severity=Severity.INFO)
    verdicts = list(engine.evaluate(f))
    fws = {v.framework for v in verdicts if v.verdict == "compliant"}
    assert {"bukukerja", "nist-ir-8547", "cnsa2"}.issubset(fws)


def test_runner_writes_framework_view_rows(tmp_db_path):
    """End-to-end: ProbeRunner persists framework_views rows when a Finding fires a rule."""
    import asyncio
    from pqcscan.core.types import Capability, ProbeFamily
    from pqcscan.probes._base import Probe
    from pqcscan.probes._registry import Registry
    from pqcscan.runner.event_bus import EventBus
    from pqcscan.runner.runner import ProbeRunner
    from pqcscan.store.repo import Repo

    class _RsaProbe(Probe):
        id = "test.rsa"
        family = ProbeFamily.AUX

        async def run(self, ctx, emit):
            emit(Finding(
                probe_id=self.id,
                algorithm="RSA-1024",
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title="weak rsa",
            ))

    repo = Repo(tmp_db_path); repo.init_schema()
    bus = EventBus()
    reg = Registry(); reg.register(_RsaProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=bus)
    scan_id = asyncio.run(runner.run(mode="user", available_capabilities=set()))
    views = repo.list_framework_views(scan_id)
    frameworks = {v.framework for v in views}
    # RSA-1024 should fire BUKUKERJA + NIST-IR-8547 + CNSA2 simultaneously.
    assert {"bukukerja", "nist-ir-8547", "cnsa2"}.issubset(frameworks)


def test_unknown_predicate_does_not_match():
    """Unknown match keys are silently false (forward-compat)."""
    f = _f("RSA-2048")
    rule = _Rule(
        match={"some_future_predicate": "value"},
        clause="x", verdict="advisory", deadline=None, note="",
    )
    assert not rule.applies(f)
