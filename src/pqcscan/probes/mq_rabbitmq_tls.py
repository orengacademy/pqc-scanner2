"""mq.rabbitmq.tls — RabbitMQ TLS config in rabbitmq.conf (Cuttlefish format).

Format: dot-separated keys, e.g. ssl_options.versions.1 = tlsv1.2.
We flag legacy versions and weak ciphers, and note whether listeners.ssl
is configured at all (informational).
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import classify_cipher_token, sev_for


_VERSION_RE = re.compile(
    r"^\s*ssl_options\.versions(?:\.\d+)?\s*=\s*(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_CIPHER_RE = re.compile(
    r"^\s*ssl_options\.ciphers(?:\.\d+)?\s*=\s*(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_LISTENER_RE = re.compile(
    r"^\s*listeners\.ssl(?:\.\d+)?\s*=\s*(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"rabbitmq.conf"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}

_BAD_PROTOS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}


class MqRabbitmqTls(Probe):
    id = "mq.rabbitmq.tls"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:mq", "bukukerja:mq", "mykripto:mq")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/rabbitmq")]

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

        for m in _VERSION_RE.finditer(text):
            value = m.group(1).strip().lower()
            line_no = text[: m.start()].count("\n") + 1
            if value in _BAD_PROTOS:
                emit(Finding(
                    probe_id=self.id, algorithm=value,
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=(f"RabbitMQ allows {value} in {path.name}:{line_no}"),
                    evidence={"path": str(path), "line": line_no,
                              "directive": "ssl_options.versions",
                              "value": value},
                ))

        for m in _CIPHER_RE.finditer(text):
            value = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            cls = classify_cipher_token(value)
            if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                emit(Finding(
                    probe_id=self.id, algorithm=value,
                    classification=cls, severity=sev_for(cls),
                    title=(f"RabbitMQ ssl_options.ciphers includes weak "
                           f"{value} in {path.name}:{line_no}"),
                    evidence={"path": str(path), "line": line_no,
                              "directive": "ssl_options.ciphers",
                              "cipher": value},
                ))

        for m in _LISTENER_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id, algorithm="RabbitMQ-TLS-listener",
                classification=Classification.INFO, severity=Severity.INFO,
                title=(f"RabbitMQ TLS listener configured "
                       f"in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": "listeners.ssl"},
            ))
