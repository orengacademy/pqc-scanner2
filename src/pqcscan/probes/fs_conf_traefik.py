from __future__ import annotations

import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_YAML_SUFFIXES = (".yml", ".yaml")
_TOML_SUFFIXES = (".toml",)
_WEAK_MIN_VERSIONS = {"VersionTLS10", "VersionTLS11"}


class FsConfTraefik(Probe):
    id = "fs.conf.traefik"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/traefik/traefik.yml"),
            Path("/etc/traefik/traefik.toml"),
            Path("/etc/traefik/dynamic"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        suffixes = _YAML_SUFFIXES + _TOML_SUFFIXES
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else [p for p in root.rglob("*") if p.suffix in suffixes]
            for path in files:
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                doc = _load(path, text)
                if doc is None:
                    continue
                for name, block in _walk_tls_options(doc):
                    self._scan_option(name, block, path, emit)

    def _scan_option(self, name: str, block: dict[str, Any], path: Path, emit: Emitter) -> None:
        min_version = block.get("minVersion")
        if isinstance(min_version, str) and min_version in _WEAK_MIN_VERSIONS:
            emit(Finding(
                probe_id=self.id,
                algorithm=min_version.upper(),
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"traefik tls option {name} sets minVersion {min_version}",
                evidence={"path": str(path), "option": name, "directive": "minVersion"},
                remediation={"snippet": "minVersion: VersionTLS12"},
            ))

        suites = block.get("cipherSuites")
        if isinstance(suites, list):
            for suite in (str(s) for s in suites):
                cls = _suite_classification(suite)
                if cls is None:
                    continue
                emit(Finding(
                    probe_id=self.id,
                    algorithm=suite,
                    classification=cls,
                    severity=_sev(cls),
                    title=f"traefik tls option {name} includes {suite}",
                    evidence={"path": str(path), "option": name, "directive": "cipherSuites"},
                ))

        curves = block.get("curvePreferences")
        if isinstance(curves, list):
            for curve in (str(c) for c in curves):
                if not (curve.startswith("CurveP") or curve.lower().startswith("secp")):
                    continue
                emit(Finding(
                    probe_id=self.id,
                    algorithm=curve,
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"traefik tls option {name} prefers classical curve {curve}",
                    evidence={"path": str(path), "option": name, "directive": "curvePreferences"},
                ))


def _load(path: Path, text: str) -> object:
    if path.suffix in _TOML_SUFFIXES:
        try:
            return tomllib.loads(text)
        except Exception:
            return None
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def _walk_tls_options(node: object) -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(node, dict):
        tls = node.get("tls")
        if isinstance(tls, dict):
            options = tls.get("options")
            if isinstance(options, dict):
                for name, block in options.items():
                    if isinstance(block, dict):
                        yield str(name), block
        for value in node.values():
            yield from _walk_tls_options(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_tls_options(item)


def _suite_classification(suite: str) -> Classification | None:
    s = suite.upper()
    if "3DES" in s or "RC4" in s or s.endswith("_CBC_SHA"):
        # SHA-1 HMAC / legacy bulk ciphers.
        return Classification.SANGAT_TINGGI
    if "_RSA_WITH" in s and "DHE" not in s:
        # Static RSA key exchange: no forward secrecy, quantum-broken kex.
        return Classification.TINGGI
    return None


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
