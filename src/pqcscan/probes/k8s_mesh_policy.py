"""k8s.mesh.policy — deep parse of service-mesh + cert-manager YAML manifests.

Complements k8s.mesh.mtls (CRD presence) by inspecting the actual policy
documents on disk: Istio PeerAuthentication / DestinationRule mTLS modes and
cert-manager Certificate / Issuer / ClusterIssuer private-key algorithms.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_MANIFEST_SUFFIXES = (".yaml", ".yml")


def _split_documents(text: str) -> list[str]:
    """Split a multi-document YAML stream on lines that are exactly ``---``."""
    docs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            docs.append("\n".join(current))
            current = []
        else:
            current.append(line)
    docs.append("\n".join(current))
    return docs


def _load_documents(text: str) -> list[dict[str, Any]]:
    """Parse a manifest into individual mapping documents, skipping junk."""
    out: list[dict[str, Any]] = []
    for chunk in _split_documents(text):
        if not chunk.strip():
            continue
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


class K8sMeshPolicy(Probe):
    id = "k8s.mesh.policy"
    family = ProbeFamily.CONTAINER
    framework_tags = ("bukukerja:k8s", "mykripto:k8s")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/kubernetes"), Path("/opt")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for suffix in _MANIFEST_SUFFIXES:
                for path in root.rglob(f"*{suffix}"):
                    self._scan_file(path, emit)

    def _scan_file(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        try:
            docs = _load_documents(text)
        except (yaml.YAMLError, ValueError):
            return
        for doc in docs:
            try:
                self._scan_doc(doc, path, emit)
            except (ValueError, AttributeError, TypeError):
                continue

    def _scan_doc(self, doc: dict[str, Any], path: Path, emit: Emitter) -> None:
        kind = str(doc.get("kind", "")).strip()
        if kind == "PeerAuthentication":
            self._peer_authentication(doc, path, emit)
        elif kind == "DestinationRule":
            self._destination_rule(doc, path, emit)
        elif kind in {"Certificate", "Issuer", "ClusterIssuer"}:
            self._cert_manager(doc, kind, path, emit)

    def _name(self, doc: dict[str, Any]) -> str:
        meta = doc.get("metadata") or {}
        if isinstance(meta, dict):
            return str(meta.get("name", "?"))
        return "?"

    def _peer_authentication(self, doc: dict[str, Any], path: Path, emit: Emitter) -> None:
        spec = doc.get("spec") or {}
        mtls = spec.get("mtls") or {}
        mode = str(mtls.get("mode", "")).strip().upper()
        if not mode:
            return
        name = self._name(doc)
        if mode in {"DISABLE", "PERMISSIVE"}:
            emit(Finding(
                probe_id=self.id,
                algorithm="mTLS",
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=f"Istio PeerAuthentication {name} mtls.mode={mode} (plaintext or downgradeable mesh traffic)",
                evidence={"path": str(path), "kind": "PeerAuthentication", "name": name, "mode": mode},
                remediation={"snippet": "spec:\n  mtls:\n    mode: STRICT"},
            ))
        elif mode == "STRICT":
            emit(Finding(
                probe_id=self.id,
                algorithm="mTLS",
                classification=Classification.INFO,
                severity=Severity.INFO,
                title=f"Istio PeerAuthentication {name} mtls.mode=STRICT",
                evidence={"path": str(path), "kind": "PeerAuthentication", "name": name, "mode": mode},
            ))

    def _destination_rule(self, doc: dict[str, Any], path: Path, emit: Emitter) -> None:
        spec = doc.get("spec") or {}
        traffic = spec.get("trafficPolicy") or {}
        tls = traffic.get("tls") or {}
        mode = str(tls.get("mode", "")).strip().upper()
        if mode != "DISABLE":
            return
        name = self._name(doc)
        emit(Finding(
            probe_id=self.id,
            algorithm="mTLS",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title=f"Istio DestinationRule {name} trafficPolicy.tls.mode=DISABLE (plaintext mesh traffic)",
            evidence={"path": str(path), "kind": "DestinationRule", "name": name, "mode": mode},
            remediation={"snippet": "spec:\n  trafficPolicy:\n    tls:\n      mode: ISTIO_MUTUAL"},
        ))

    def _cert_manager(self, doc: dict[str, Any], kind: str, path: Path, emit: Emitter) -> None:
        spec = doc.get("spec") or {}
        private_key = spec.get("privateKey") or {}
        algorithm = str(private_key.get("algorithm", "")).strip().upper()
        if not algorithm:
            return
        size = private_key.get("size")
        try:
            size_int = int(size) if size is not None else None
        except (ValueError, TypeError):
            size_int = None
        name = self._name(doc)
        weak_rsa = algorithm == "RSA" and size_int is not None and size_int < 2048
        if weak_rsa:
            emit(Finding(
                probe_id=self.id,
                algorithm=f"RSA-{size_int}",
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=f"cert-manager {kind} {name} privateKey RSA-{size_int} (<2048, classical/quantum-vulnerable)",
                evidence={"path": str(path), "kind": kind, "name": name,
                          "algorithm": algorithm, "size": size_int},
                remediation={"snippet": "spec:\n  privateKey:\n    algorithm: RSA\n    size: 3072"},
            ))
        else:
            alg_label = f"RSA-{size_int}" if algorithm == "RSA" and size_int else algorithm
            emit(Finding(
                probe_id=self.id,
                algorithm=alg_label,
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=f"cert-manager {kind} {name} privateKey {alg_label} (classical/quantum-vulnerable)",
                evidence={"path": str(path), "kind": kind, "name": name,
                          "algorithm": algorithm, "size": size_int},
            ))


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]
