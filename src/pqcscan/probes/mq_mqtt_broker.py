"""mq.mqtt.broker — Mosquitto / generic MQTT broker config (mosquitto.conf).

Mosquitto config is space-separated key value pairs. We flag legacy
TLS versions, weak ciphers, and unauthenticated listeners.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import classify_cipher_token, sev_for

_TLS_VERSION_RE = re.compile(
    r"^\s*tls_version\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_CIPHERS_RE = re.compile(
    r"^\s*ciphers\s+(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_ANON_RE = re.compile(
    r"^\s*allow_anonymous\s+(true|false|yes|no|1|0)\b",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"mosquitto.conf"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}

_BAD_PROTOS = {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv2", "sslv3"}


class MqMqttBroker(Probe):
    id = "mq.mqtt.broker"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:mq", "bukukerja:mq", "mykripto:mq")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/mosquitto")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            walker = [root] if root.is_file() else list(root.rglob("*"))
            for path in walker:
                if not path.is_file():
                    continue
                if any(part in _EXCLUDE_DIRS for part in path.parts):
                    continue
                if path.name not in _NAMES:
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return

        for m in _TLS_VERSION_RE.finditer(text):
            value = m.group(1).strip().lower()
            line_no = text[: m.start()].count("\n") + 1
            if value in _BAD_PROTOS:
                emit(Finding(
                    probe_id=self.id, algorithm=value,
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=(f"Mosquitto tls_version={value} "
                           f"in {path.name}:{line_no}"),
                    evidence={"path": str(path), "line": line_no,
                              "directive": "tls_version", "value": value},
                ))

        for m in _CIPHERS_RE.finditer(text):
            value = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            for tok in re.split(r"[:,\s]+", value):
                tok = tok.strip()
                if not tok:
                    continue
                cls = classify_cipher_token(tok)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id, algorithm=tok,
                        classification=cls, severity=sev_for(cls),
                        title=(f"Mosquitto ciphers includes weak {tok} "
                               f"in {path.name}:{line_no}"),
                        evidence={"path": str(path), "line": line_no,
                                  "directive": "ciphers", "cipher": tok},
                    ))

        for m in _ANON_RE.finditer(text):
            value = m.group(1).strip().lower()
            line_no = text[: m.start()].count("\n") + 1
            if value in {"true", "yes", "1"}:
                emit(Finding(
                    probe_id=self.id, algorithm="MQTT-anonymous",
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=(f"Mosquitto allow_anonymous=true "
                           f"in {path.name}:{line_no}"),
                    evidence={"path": str(path), "line": line_no,
                              "directive": "allow_anonymous"},
                ))
