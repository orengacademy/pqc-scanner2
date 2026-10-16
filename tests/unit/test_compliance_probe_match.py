"""probe_id / probe_id_prefix / probe_family match keys."""
from pqcscan.compliance.engine import ComplianceEngine, _Rule, family_of
from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.probes._registry import default_registry


def _f(probe_id: str, alg: str = "plain-Modbus",
       cls: Classification = Classification.SANGAT_TINGGI) -> Finding:
    return Finding(probe_id=probe_id, algorithm=alg, classification=cls,
                   severity=Severity.HIGH, title="t")


def test_family_of_follows_the_registry():
    assert all(family_of(p.id) == p.family.value for p in default_registry().all())
    assert family_of("no.such.probe") is None


def test_probe_match_keys():
    assert _Rule(match={"probe_id": "ot.modbus.tcp"}, clause="c", verdict="v",
                 deadline=None, note="").applies(_f("ot.modbus.tcp"))
    assert _Rule(match={"probe_id_prefix": "ot.opc_ua"}, clause="c", verdict="v",
                 deadline=None, note="").applies(_f("ot.opc_ua.endpoint_security"))
    assert not _Rule(match={"probe_family": "ot"}, clause="c", verdict="v",
                     deadline=None, note="").applies(_f("net.tls.https"))


def test_nacsa_ot_no_crypto_rule_fires_on_plain_ot_protocol():
    verdicts = [v for v in ComplianceEngine().evaluate(_f("ot.modbus.tcp"))
                if v.clause == "NACSA-9:ot-no-crypto"]
    assert verdicts and verdicts[0].verdict == "non-compliant"
    # An unreachable-endpoint INFO row must not trip it.
    assert not [v for v in ComplianceEngine().evaluate(
        _f("ot.modbus.tcp", "N/A", Classification.INFO)) if v.clause == "NACSA-9:ot-no-crypto"]
