from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_PROTOCOL_RE = re.compile(r"^\s*SSLProtocol\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_CIPHERS_RE = re.compile(r"^\s*SSLCipherSuite\s+(.+)$", re.IGNORECASE | re.MULTILINE)


class FsConfApache(Probe):
    id = "fs.conf.apache"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/apache2/apache2.conf"),
            Path("/etc/apache2/mods-enabled"),
            Path("/etc/httpd/conf"),
            Path("/etc/httpd/conf.d"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else list(root.rglob("*.conf"))
            for path in files:
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        for m in _PROTOCOL_RE.finditer(text):
            tokens = m.group(1).strip().split()
            for token in tokens:
                t = token.lstrip("+").lstrip("-")
                if t.upper() in {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=t.upper(),
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"Apache SSLProtocol allows {t}",
                        evidence={"path": str(path), "directive": "SSLProtocol"},
                        remediation={"snippet": "SSLProtocol -all +TLSv1.2 +TLSv1.3"},
                    ))

        for m in _CIPHERS_RE.finditer(text):
            cipher_str = m.group(1).strip().strip('"').strip("'")
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
                        title=f"Apache SSLCipherSuite includes {token}",
                        evidence={
                            "path": str(path),
                            "directive": "SSLCipherSuite",
                            "list": cipher_str,
                        },
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
