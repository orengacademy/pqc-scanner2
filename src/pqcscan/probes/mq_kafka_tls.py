"""mq.kafka.tls — Kafka broker TLS config in server.properties.

Java-style key=value lines. We flag legacy TLS protocols and weak ciphers.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import classify_cipher_token, sev_for

_PROTO_RE = re.compile(
    r"^\s*ssl\.enabled\.protocols\s*=\s*([^\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_CIPHER_RE = re.compile(
    r"^\s*ssl\.cipher\.suites\s*=\s*([^\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_INTER_RE = re.compile(
    r"^\s*security\.inter\.broker\.protocol\s*=\s*([^\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"server.properties"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class MqKafkaTls(Probe):
    id = "mq.kafka.tls"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:mq", "bukukerja:mq", "mykripto:mq")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/kafka"), Path("/opt/kafka/config"),
            Path("/etc/confluent"),
        ]

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

        for m in _PROTO_RE.finditer(text):
            value = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            for tok in re.split(r"[,\s]+", value):
                tok = tok.strip()
                if tok in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}:
                    emit(Finding(
                        probe_id=self.id, algorithm=tok,
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=(f"Kafka allows {tok} via ssl.enabled.protocols "
                               f"in {path.name}:{line_no}"),
                        evidence={"path": str(path), "line": line_no,
                                  "directive": "ssl.enabled.protocols",
                                  "value": tok},
                    ))

        for m in _CIPHER_RE.finditer(text):
            value = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            for tok in re.split(r"[,\s:]+", value):
                tok = tok.strip()
                if not tok:
                    continue
                cls = classify_cipher_token(tok)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id, algorithm=tok,
                        classification=cls, severity=sev_for(cls),
                        title=(f"Kafka ssl.cipher.suites includes weak {tok} "
                               f"in {path.name}:{line_no}"),
                        evidence={"path": str(path), "line": line_no,
                                  "directive": "ssl.cipher.suites",
                                  "cipher": tok},
                    ))

        for m in _INTER_RE.finditer(text):
            value = m.group(1).strip().upper()
            line_no = text[: m.start()].count("\n") + 1
            if value == "PLAINTEXT":
                emit(Finding(
                    probe_id=self.id, algorithm="Kafka-PLAINTEXT-broker",
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=(f"Kafka inter-broker protocol is PLAINTEXT "
                           f"in {path.name}:{line_no}"),
                    evidence={"path": str(path), "line": line_no,
                              "directive": "security.inter.broker.protocol"},
                ))
