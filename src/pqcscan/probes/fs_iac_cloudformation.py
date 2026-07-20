"""fs.iac.cloudformation — scan CloudFormation templates and cert-manager
Kubernetes manifests for quantum-vulnerable or weak crypto configuration.

A YAML/JSON file is treated as CloudFormation only when it declares
``AWSTemplateFormatVersion`` or a top-level ``Resources`` map containing
``AWS::`` types, so arbitrary YAML on disk is not scanned. cert-manager
manifests (``apiVersion: cert-manager.io/*``) are additionally inspected.
Parsing is stdlib-only (``json`` + the already-present ``yaml``).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.alg import normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_SUFFIXES = (".yaml", ".yml", ".json")
_EXCLUDE_DIRS = frozenset({".git", ".terraform", "node_modules", "vendor"})
_MAX_PER_FILE = 200
_LEGACY_SSL_POLICY = "ELBSECURITYPOLICY-2016-08"


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics
    (``!Ref``, ``!GetAtt``, ...) instead of raising on the unknown tag."""


def _ignore_multi(loader: yaml.Loader, tag_suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


_CfnLoader.add_multi_constructor("!", _ignore_multi)


def _digits(value: str) -> int | None:
    m = re.search(r"\d+", value)
    return int(m.group()) if m else None


def _rsa_cls(bits: int | None) -> Classification:
    return Classification.SANGAT_TINGGI if bits is not None and bits < 3072 else Classification.TINGGI


def _key_spec_finding(value: str) -> tuple[str, Classification] | None:
    """Classify an AWS KMS KeySpec value. Returns (algorithm, class) or None
    for symmetric / unrecognised specs that are not quantum-vulnerable."""
    v = value.upper()
    if v.startswith("SYMMETRIC"):
        return None  # AES-256 symmetric key — quantum-safe
    if v.startswith("RSA"):
        bits = _digits(v)
        return (f"RSA-{bits}" if bits else "RSA", _rsa_cls(bits))
    if v.startswith("ECC") or v.startswith("EC"):
        return (normalise("ECDSA"), Classification.TINGGI)
    return None


class FsIacCloudformation(Probe):
    id = "fs.iac.cloudformation"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path.cwd()]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else self._iter_files(root)
            for path in files:
                if path in seen:
                    continue
                seen.add(path)
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                if not _looks_relevant(text):
                    continue
                count = 0
                for doc in _parse(text, path.suffix.lower()):
                    if not isinstance(doc, dict):
                        continue
                    for finding in self._scan_doc(doc, path):
                        if count >= _MAX_PER_FILE:
                            return
                        emit(finding)
                        count += 1

    @staticmethod
    def _iter_files(root: Path) -> list[Path]:
        out: list[Path] = []
        for p in root.rglob("*"):
            if p.suffix.lower() not in _SUFFIXES:
                continue
            if any(part in _EXCLUDE_DIRS for part in p.parts):
                continue
            if p.is_file():
                out.append(p)
        return out

    def _scan_doc(self, doc: dict[str, Any], path: Path) -> list[Finding]:
        api = doc.get("apiVersion")
        if isinstance(api, str) and api.startswith("cert-manager.io"):
            return self._scan_certmanager(doc, path)
        if _is_cfn(doc):
            return self._scan_cfn(doc, path)
        return []

    def _emit(
        self, path: Path, resource_type: str, logical_or_kind: str,
        field: str, value: str, algorithm: str, cls: Classification,
    ) -> Finding:
        return Finding(
            probe_id=self.id,
            algorithm=algorithm,
            classification=cls,
            severity=sev_for(cls),
            title=f"cloudformation {resource_type} {field}={value} ({algorithm}) in {path}",
            evidence={
                "path": str(path),
                "resource_type": resource_type,
                "logical_id_or_kind": logical_or_kind,
                "field": field,
                "value": value,
            },
        )

    def _scan_cfn(self, doc: dict[str, Any], path: Path) -> list[Finding]:
        out: list[Finding] = []
        resources = doc.get("Resources")
        if not isinstance(resources, dict):
            return out
        for logical_id, res in resources.items():
            if not isinstance(res, dict):
                continue
            rtype = res.get("Type")
            if not isinstance(rtype, str):
                continue
            props = res.get("Properties")
            props = props if isinstance(props, dict) else {}

            if rtype == "AWS::KMS::Key":
                spec = props.get("KeySpec")
                if isinstance(spec, str):
                    result = _key_spec_finding(spec)
                    if result:
                        out.append(self._emit(path, rtype, str(logical_id),
                                               "KeySpec", spec, *result))

            elif rtype == "AWS::CertificateManager::Certificate":
                ka = props.get("KeyAlgorithm")
                if isinstance(ka, str):
                    up = ka.upper()
                    if up.startswith("RSA"):
                        bits = _digits(up)
                        out.append(self._emit(path, rtype, str(logical_id), "KeyAlgorithm",
                                              ka, f"RSA-{bits}" if bits else "RSA", _rsa_cls(bits)))
                    elif up.startswith("EC"):
                        out.append(self._emit(path, rtype, str(logical_id), "KeyAlgorithm",
                                              ka, normalise("ECDSA"), Classification.TINGGI))

            elif rtype == "AWS::ElasticLoadBalancingV2::Listener":
                sp = props.get("SslPolicy")
                if isinstance(sp, str):
                    up = sp.upper()
                    if "TLS-1-0" in up or "TLS-1-1" in up or up == _LEGACY_SSL_POLICY:
                        out.append(self._emit(path, rtype, str(logical_id), "SslPolicy",
                                              sp, "TLS-LEGACY", Classification.TINGGI))
                proto = props.get("Protocol")
                if isinstance(proto, str) and proto.upper() == "HTTP":
                    out.append(Finding(
                        probe_id=self.id,
                        algorithm="PLAINTEXT",
                        classification=Classification.INFO,
                        severity=Severity.INFO,
                        title=f"cloudformation {rtype} Protocol=HTTP (no TLS) in {path}",
                        evidence={
                            "path": str(path),
                            "resource_type": rtype,
                            "logical_id_or_kind": str(logical_id),
                            "field": "Protocol",
                            "value": proto,
                        },
                    ))
        return out

    def _scan_certmanager(self, doc: dict[str, Any], path: Path) -> list[Finding]:
        out: list[Finding] = []
        kind = doc.get("kind")
        if kind not in {"Certificate", "Issuer", "ClusterIssuer"}:
            return out
        spec = doc.get("spec")
        spec = spec if isinstance(spec, dict) else {}
        pk = spec.get("privateKey")
        if not isinstance(pk, dict):
            return out
        algo = pk.get("algorithm")
        if not isinstance(algo, str):
            return out
        up = algo.upper()
        size = pk.get("size")
        bits = size if isinstance(size, int) else _digits(str(size)) if size is not None else None
        if up == "RSA":
            bits = bits if bits is not None else 2048  # cert-manager RSA default
            out.append(self._emit(path, str(doc.get("apiVersion")), str(kind),
                                  "spec.privateKey.algorithm", algo,
                                  f"RSA-{bits}", _rsa_cls(bits)))
        elif up == "ECDSA":
            out.append(self._emit(path, str(doc.get("apiVersion")), str(kind),
                                  "spec.privateKey.algorithm", algo,
                                  normalise("ECDSA"), Classification.TINGGI))
        return out


def _looks_relevant(text: str) -> bool:
    if "cert-manager.io" in text:
        return True
    if "AWSTemplateFormatVersion" in text:
        return True
    return "AWS::" in text and "Resources" in text


def _is_cfn(doc: dict[str, Any]) -> bool:
    if "AWSTemplateFormatVersion" in doc:
        return True
    resources = doc.get("Resources")
    if isinstance(resources, dict):
        for res in resources.values():
            if isinstance(res, dict) and isinstance(res.get("Type"), str) \
                    and res["Type"].startswith("AWS::"):
                return True
    return False


def _parse(text: str, suffix: str) -> list[Any]:
    if suffix == ".json":
        try:
            return [json.loads(text)]
        except (ValueError, TypeError):
            return []
    try:
        return [d for d in yaml.load_all(text, Loader=_CfnLoader) if d is not None]
    except yaml.YAMLError:
        return []
    except Exception:
        return []
