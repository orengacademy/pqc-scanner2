from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_PROTOCOLS_RE = re.compile(r"^\s*protocols\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_CURVES_RE = re.compile(r"^\s*curves\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_KEY_TYPE_RE = re.compile(r"^\s*key_type\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_CIPHER_SUITES_RE = re.compile(r"^\s*cipher_suites\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)

# Caddy is TLS 1.2+/safe by default; these only appear as explicit weakenings.
_WEAK_PROTOCOLS = {"ssl3", "tls1.0", "tls1.1"}

_KEY_TYPE_MAP = {
    "p256": "ECDSA-P256",
    "p384": "ECDSA-P384",
    "rsa2048": "RSA-2048",
    "rsa4096": "RSA-4096",
    "ed25519": "Ed25519",
}

_CURVE_MAP = {
    "secp256r1": "ECDSA-P256",
    "secp384r1": "ECDSA-P384",
    "secp521r1": "ECDSA-P521",
    "x25519": "X25519",
}

_WEAK = {Classification.SANGAT_TINGGI, Classification.TINGGI}


class FsConfCaddy(Probe):
    id = "fs.conf.caddy"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/caddy/Caddyfile"),
            Path("/etc/caddy"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            if root.is_file():
                files = [root]
            else:
                files = [
                    p for p in root.rglob("*")
                    if p.name == "Caddyfile" or p.suffix in {".caddyfile", ".json"}
                ]
            for path in files:
                if not path.is_file():
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                if path.suffix == ".json":
                    self._scan_json(text, path, emit)
                else:
                    self._scan_caddyfile(text, path, emit)

    def _scan_caddyfile(self, text: str, path: Path, emit: Emitter) -> None:
        for m in _PROTOCOLS_RE.finditer(text):
            for proto in m.group(1).split():
                if proto.lower() in _WEAK_PROTOCOLS:
                    self._emit_weak_protocol(proto, "protocols", path, emit)

        for m in _CURVES_RE.finditer(text):
            tokens = m.group(1).split()
            classified = [(t, _CURVE_MAP.get(t.lower(), t)) for t in tokens]
            # A PQC hybrid group anywhere in the list keeps handshakes safe.
            if any(classify(name) is Classification.PQC_READY for _, name in classified):
                continue
            for token, name in classified:
                cls = classify(name)
                if cls in _WEAK:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=normalise(name),
                        classification=cls,
                        severity=_sev(cls),
                        title=f"caddy tls curves includes {token}",
                        evidence={"path": str(path), "directive": "curves", "list": m.group(1)},
                    ))

        for m in _KEY_TYPE_RE.finditer(text):
            token = m.group(1)
            name = _KEY_TYPE_MAP.get(token.lower())
            if name is None:
                continue
            cls = classify(name)
            if cls in _WEAK:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=normalise(name),
                    classification=cls,
                    severity=_sev(cls),
                    title=f"caddy tls key_type is {token}",
                    evidence={"path": str(path), "directive": "key_type"},
                ))

        for m in _CIPHER_SUITES_RE.finditer(text):
            for token in m.group(1).split():
                self._emit_weak_cipher(token, "cipher_suites", m.group(1), path, emit)

    def _scan_json(self, text: str, path: Path, emit: Emitter) -> None:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return
        for policy in _iter_tls_policies(data):
            proto_min = policy.get("protocol_min")
            if isinstance(proto_min, str) and proto_min.lower() in _WEAK_PROTOCOLS:
                self._emit_weak_protocol(proto_min, "tls_connection_policies.protocol_min", path, emit)
            suites = policy.get("cipher_suites")
            if isinstance(suites, list):
                for token in suites:
                    if isinstance(token, str):
                        self._emit_weak_cipher(
                            token, "tls_connection_policies.cipher_suites", ", ".join(map(str, suites)), path, emit,
                        )

    def _emit_weak_protocol(self, proto: str, directive: str, path: Path, emit: Emitter) -> None:
        emit(Finding(
            probe_id=self.id,
            algorithm=proto.upper(),
            classification=Classification.SANGAT_TINGGI,
            severity=Severity.CRIT,
            title=f"caddy {directive} enables {proto}",
            evidence={"path": str(path), "directive": directive},
            remediation={"snippet": "protocols tls1.2 tls1.3"},
        ))

    def _emit_weak_cipher(self, token: str, directive: str, listing: str, path: Path, emit: Emitter) -> None:
        alg, cls = _classify_cipher(token)
        if cls in _WEAK:
            emit(Finding(
                probe_id=self.id,
                algorithm=alg,
                classification=cls,
                severity=_sev(cls),
                title=f"caddy {directive} includes {token}",
                evidence={"path": str(path), "directive": directive, "list": listing},
            ))


def _classify_cipher(token: str) -> tuple[str, Classification]:
    """Classify a cipher-suite token, falling back to its weakest component.

    Caddy uses Go-style suite names (TLS_RSA_WITH_3DES_EDE_CBC_SHA); the whole
    name never matches classify(), so also check each underscore-separated part
    for hard-broken primitives such as RC4/3DES/DES/MD5.
    """
    cls = classify(token)
    if cls not in _WEAK:
        for part in token.replace("-", "_").split("_"):
            if part and classify(part) is Classification.SANGAT_TINGGI:
                return normalise(part), Classification.SANGAT_TINGGI
    return normalise(token), cls


def _iter_tls_policies(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "tls_connection_policies" and isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
            else:
                yield from _iter_tls_policies(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_tls_policies(item)


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
