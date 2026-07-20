import pytest

from pqcscan.core.confidence import HIGH, LOW, MEDIUM, assess
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Probe
from pqcscan.probes._registry import Registry
from pqcscan.runner.event_bus import EventBus
from pqcscan.runner.runner import ProbeRunner
from pqcscan.store.repo import Repo


def test_structured_parse_is_high():
    assert assess("fs.cert.x509", {}) == HIGH
    assert assess("host.openssl.ciphers", {}) == HIGH
    assert assess("net.tls.cert_chain_tls13", {}) == HIGH


def test_code_regex_is_medium():
    assert assess("code.crypto_primitives", {"file": "/app/main.py"}) == MEDIUM
    assert assess("code.ts.python", {"file": "/srv/app/crypto.py"}) == MEDIUM


def test_code_in_test_file_is_low():
    assert assess("code.crypto_primitives", {"file": "/app/tests/test_x.py"}) == LOW
    assert assess("code.crypto_primitives", {"file": "/app/foo.spec.js"}) == LOW
    assert assess("code.crypto_primitives", {"file": "/app/node_modules/x/y.js"}) == LOW


def test_code_in_comment_is_low():
    assert assess("code.crypto_primitives",
                  {"file": "/app/main.go", "snippet": "// uses md5 here"}) == LOW
    assert assess("code.ts.python",
                  {"file": "/app/x.py", "snippet": "# legacy RSA-1024 note"}) == LOW


def test_sbom_and_cve_are_medium():
    assert assess("sbom.crypto_map", {}) == MEDIUM
    assert assess("cve.osv_offline", {}) == MEDIUM


def test_sniff_and_advertised_are_low():
    assert assess("fs.cert.sniff", {}) == LOW
    assert assess("net.tls.kex_groups", {"advertised": True}) == LOW


def test_verified_beats_family_default():
    assert assess("code.crypto_primitives", {"verified": True}) == HIGH


def test_probe_can_force_confidence():
    assert assess("fs.cert.x509", {"confidence": "low"}) == LOW


class _CodeProbe(Probe):
    id = "code.crypto_primitives"
    family = ProbeFamily.CODE

    async def run(self, ctx, emit):
        emit(Finding(
            probe_id=self.id, algorithm="MD5",
            classification=Classification.SANGAT_TINGGI, severity=Severity.CRIT,
            title="md5 in a comment",
            evidence={"file": "/app/tests/test_a.py", "snippet": "# md5"},
        ))


@pytest.mark.asyncio
async def test_runner_persists_confidence(tmp_db_path):
    repo = Repo(tmp_db_path); repo.init_schema()
    reg = Registry(); reg.register(_CodeProbe())
    runner = ProbeRunner(registry=reg, repo=repo, bus=EventBus())
    scan_id = await runner.run(mode="user", available_capabilities=set())
    f = repo.list_findings(scan_id)[0]
    # regex hit inside a test file -> low confidence, persisted in evidence
    assert f.evidence["confidence"] == "low"
