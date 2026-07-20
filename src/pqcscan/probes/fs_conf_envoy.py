from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_SUFFIXES = (".yaml", ".yml", ".json")
_TLS_PARAMS_KEYS = {"tls_params", "tlsParams", "TlsParameters"}
_WEAK_PROTOCOLS = {"TLSV1_0", "TLSV1_1"}
# Envoy curve names -> canonical algorithm names for classify().
_CURVE_MAP = {
    "P-256": "ECDH-P256",
    "P-384": "ECDH-P384",
    "P-521": "ECDH-P521",
    "X25519": "X25519",
}


class FsConfEnvoy(Probe):
    id = "fs.conf.envoy"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/envoy/envoy.yaml"),
            Path("/etc/envoy"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else [p for p in root.rglob("*") if p.suffix in _SUFFIXES]
            for path in files:
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                doc = _load(text)
                if doc is None:
                    continue
                for params in _walk_tls_params(doc):
                    self._scan_params(params, path, emit)

    def _scan_params(self, params: dict[str, Any], path: Path, emit: Emitter) -> None:
        for directive in ("tls_minimum_protocol_version", "tls_maximum_protocol_version"):
            value = params.get(directive)
            if isinstance(value, str) and value.upper() in _WEAK_PROTOCOLS:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=value.upper(),
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=f"envoy tls_params sets {directive} to {value}",
                    evidence={"path": str(path), "directive": directive},
                    remediation={"snippet": f"{directive}: TLSv1_2"},
                ))

        for token in _tokens(params.get("cipher_suites")):
            token = token.lstrip("!").lstrip("+").lstrip("-")
            if not token:
                continue
            cls = classify(token)
            if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=normalise(token),
                    classification=cls,
                    severity=_sev(cls),
                    title=f"envoy cipher_suites includes {token}",
                    evidence={"path": str(path), "directive": "cipher_suites"},
                ))

        for token in _tokens(params.get("ecdh_curves")):
            mapped = _CURVE_MAP.get(token, token)
            cls = classify(mapped)
            if cls is Classification.PQC_READY:
                continue
            if cls not in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                # All classical ECDH key agreement is quantum-broken.
                cls = Classification.TINGGI
            emit(Finding(
                probe_id=self.id,
                algorithm=normalise(mapped),
                classification=cls,
                severity=_sev(cls),
                title=f"envoy ecdh_curves includes {token}",
                evidence={"path": str(path), "directive": "ecdh_curves"},
                remediation={"snippet": "ecdh_curves: [X25519MLKEM768, X25519]"},
            ))


def _load(text: str) -> object:
    try:
        return yaml.safe_load(text)
    except Exception:
        pass
    try:
        return json.loads(text)
    except Exception:
        return None


def _walk_tls_params(node: object) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _TLS_PARAMS_KEYS and isinstance(value, dict):
                yield value
            yield from _walk_tls_params(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_tls_params(item)


def _tokens(value: object) -> list[str]:
    if isinstance(value, str):
        items = value.split(":")
    elif isinstance(value, list):
        items = [str(v) for v in value]
    else:
        return []
    return [t for t in (i.strip() for i in items) if t]


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
