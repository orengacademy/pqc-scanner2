from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_CIPHERS_RE = re.compile(
    r"^\s*(ssl-default-bind-ciphers|ssl-default-bind-ciphersuites)\s+(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_MIN_VER_RE = re.compile(r"ssl-min-ver\s+(\S+)", re.IGNORECASE)
_FORCE_RE = re.compile(r"\b(no-tlsv13|force-tlsv10|force-tlsv11|force-sslv3)\b", re.IGNORECASE)

# SSLv3, TLSv1.0 and TLSv1.1 are weak minimum versions.
_WEAK_MIN_VERS = {"SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}

_FORCE_MAP = {
    "no-tlsv13": "TLSV1.3",
    "force-tlsv10": "TLSV1.0",
    "force-tlsv11": "TLSV1.1",
    "force-sslv3": "SSLV3",
}


class FsConfHaproxy(Probe):
    id = "fs.conf.haproxy"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/haproxy/haproxy.cfg"),
            Path("/etc/haproxy/conf.d"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else list(root.rglob("*.cfg"))
            for path in files:
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        for m in _CIPHERS_RE.finditer(text):
            directive = m.group(1).lower()
            cipher_str = m.group(2).strip().strip('"').strip("'")
            for token in cipher_str.split(":"):
                token = token.strip().lstrip("!").lstrip("+").lstrip("-")
                if not token or token.upper() in {"HIGH", "MEDIUM", "LOW", "ALL", "DEFAULT"}:
                    continue
                cls = classify(token)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=normalise(token),
                        classification=cls,
                        severity=_sev(cls),
                        title=f"haproxy {directive} includes {token}",
                        evidence={
                            "path": str(path),
                            "directive": directive,
                            "list": cipher_str,
                        },
                    ))

        for m in _MIN_VER_RE.finditer(text):
            proto = m.group(1)
            proto_canon = proto.upper()
            if proto_canon in _WEAK_MIN_VERS:
                emit(Finding(
                    probe_id=self.id,
                    algorithm=proto_canon,
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.CRIT,
                    title=f"haproxy ssl-min-ver allows {proto}",
                    evidence={"path": str(path), "directive": "ssl-min-ver"},
                    remediation={"snippet": "ssl-default-bind-options ssl-min-ver TLSv1.2"},
                ))

        for m in _FORCE_RE.finditer(text):
            opt = m.group(1).lower()
            emit(Finding(
                probe_id=self.id,
                algorithm=_FORCE_MAP[opt],
                classification=Classification.SANGAT_TINGGI,
                severity=Severity.CRIT,
                title=f"haproxy option {opt} weakens TLS protocol negotiation",
                evidence={"path": str(path), "directive": opt},
                remediation={"snippet": "ssl-default-bind-options ssl-min-ver TLSv1.2"},
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
