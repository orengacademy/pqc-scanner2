from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.k8s_mesh_policy import (
    K8sMeshPolicy,
    _load_documents,
    _sev,
    _split_documents,
)

PEER_DISABLE = """
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: DISABLE
"""

PEER_PERMISSIVE = """
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: perm
spec:
  mtls:
    mode: PERMISSIVE
"""

PEER_STRICT = """
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: locked
spec:
  mtls:
    mode: STRICT
"""

DEST_DISABLE = """
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: legacy
spec:
  host: legacy.svc.cluster.local
  trafficPolicy:
    tls:
      mode: DISABLE
"""

CERT_WEAK_RSA = """
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: weak
spec:
  privateKey:
    algorithm: RSA
    size: 1024
"""

CERT_RSA_2048 = """
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ok
spec:
  privateKey:
    algorithm: RSA
    size: 2048
"""

ISSUER_ECDSA = """
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ec
spec:
  privateKey:
    algorithm: ECDSA
"""

OTHER_KIND = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: ignore
data:
  foo: bar
"""


def _collect(probe: K8sMeshPolicy, text: str, tmp_path: Path) -> list[Finding]:
    (tmp_path / "manifest.yaml").write_text(text)
    findings: list[Finding] = []

    import asyncio

    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    asyncio.run(probe.run(ctx, findings.append))
    return findings


# ---- pure helpers -------------------------------------------------------


def test_split_documents_on_triple_dash():
    text = "a: 1\n---\nb: 2\n---\nc: 3"
    docs = _split_documents(text)
    assert len(docs) == 3
    assert "a: 1" in docs[0]
    assert "b: 2" in docs[1]
    assert "c: 3" in docs[2]


def test_split_ignores_indented_dashes():
    # a "---" that is not a standalone line must not split
    text = "items:\n  - a\n  - b"
    docs = _split_documents(text)
    assert len(docs) == 1


def test_load_documents_skips_non_mappings_and_blanks():
    text = "\n---\n- just\n- a\n- list\n---\nkind: Certificate\n"
    docs = _load_documents(text)
    assert len(docs) == 1
    assert docs[0]["kind"] == "Certificate"


def test_load_documents_skips_bad_yaml():
    text = "kind: Good\n---\n: : : not valid : :\n---\nkind: AlsoGood\n"
    docs = _load_documents(text)
    kinds = [d.get("kind") for d in docs]
    assert "Good" in kinds
    assert "AlsoGood" in kinds


def test_sev_mapping():
    assert _sev(Classification.TINGGI) is Severity.HIGH
    assert _sev(Classification.SEDERHANA) is Severity.MED
    assert _sev(Classification.INFO) is Severity.INFO


# ---- probe wiring -------------------------------------------------------


def test_metadata():
    p = K8sMeshPolicy()
    assert p.id == "k8s.mesh.policy"
    assert p.family is ProbeFamily.CONTAINER
    assert p.framework_tags == ("bukukerja:k8s", "mykripto:k8s")


@pytest.mark.asyncio
async def test_applies_true_when_root_exists(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await p.applies(ctx) is True


@pytest.mark.asyncio
async def test_applies_false_when_no_root(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path / "nope"])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert await p.applies(ctx) is False


# ---- detections ---------------------------------------------------------


def test_peer_disable_high(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, PEER_DISABLE, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH
    assert f.evidence["mode"] == "DISABLE"


def test_peer_permissive_high(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, PEER_PERMISSIVE, tmp_path)
    assert len(findings) == 1
    assert findings[0].classification is Classification.TINGGI
    assert findings[0].severity is Severity.HIGH


def test_peer_strict_info(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, PEER_STRICT, tmp_path)
    assert len(findings) == 1
    assert findings[0].classification is Classification.INFO
    assert findings[0].severity is Severity.INFO


def test_destination_rule_disable_high(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, DEST_DISABLE, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH
    assert f.evidence["kind"] == "DestinationRule"


def test_cert_weak_rsa_high(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, CERT_WEAK_RSA, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.classification is Classification.TINGGI
    assert f.severity is Severity.HIGH
    assert f.algorithm == "RSA-1024"


def test_cert_rsa_2048_med(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, CERT_RSA_2048, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED
    assert f.algorithm == "RSA-2048"


def test_issuer_ecdsa_med(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, ISSUER_ECDSA, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.classification is Classification.SEDERHANA
    assert f.severity is Severity.MED
    assert f.algorithm == "ECDSA"


def test_other_kind_ignored(tmp_path):
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, OTHER_KIND, tmp_path)
    assert findings == []


def test_multi_document_file(tmp_path):
    text = "\n---\n".join([PEER_DISABLE, DEST_DISABLE, CERT_WEAK_RSA, OTHER_KIND])
    p = K8sMeshPolicy(roots=[tmp_path])
    findings = _collect(p, text, tmp_path)
    assert len(findings) == 3


@pytest.mark.asyncio
async def test_bad_yaml_file_does_not_crash(tmp_path):
    (tmp_path / "broken.yaml").write_text("kind: PeerAuthentication\nspec: {mtls: {mode: : :}}")
    p = K8sMeshPolicy(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    findings: list[Finding] = []
    await p.run(ctx, findings.append)
    assert findings == []
