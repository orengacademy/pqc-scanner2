"""mq.nats.tls — NATS broker TLS config (HOCON-ish nats-server.conf).

NATS allows the operator to override Go's default TLS cipher list with
tls.cipher_suites = [...]; we flag any legacy cipher names that appear.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import classify_cipher_token, sev_for


_CIPHERS_BLOCK_RE = re.compile(
    r"cipher_suites\s*[:=]\s*\[([^\]]+)\]",
    re.IGNORECASE | re.DOTALL,
)
_TLS_PRESENT_RE = re.compile(
    r"^\s*tls\s*[:=]?\s*\{",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"nats-server.conf", "nats.conf"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class MqNatsTls(Probe):
    id = "mq.nats.tls"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:mq", "bukukerja:mq", "mykripto:mq")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc/nats"), Path("/etc/nats-server")]

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

        if _TLS_PRESENT_RE.search(text):
            emit(Finding(
                probe_id=self.id, algorithm="NATS-TLS-block",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"NATS TLS block configured in {path.name}",
                evidence={"path": str(path), "directive": "tls"},
            ))

        for m in _CIPHERS_BLOCK_RE.finditer(text):
            value = m.group(1)
            line_no = text[: m.start()].count("\n") + 1
            for tok in re.split(r"[\s,]+", value):
                tok = tok.strip().strip('"\'')
                if not tok:
                    continue
                cls = classify_cipher_token(tok)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id, algorithm=tok,
                        classification=cls, severity=sev_for(cls),
                        title=(f"NATS tls.cipher_suites includes weak {tok} "
                               f"in {path.name}:{line_no}"),
                        evidence={"path": str(path), "line": line_no,
                                  "directive": "tls.cipher_suites",
                                  "cipher": tok},
                    ))
