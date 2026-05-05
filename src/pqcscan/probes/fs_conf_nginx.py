from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_PROTOCOL_RE = re.compile(r"^\s*ssl_protocols\s+(.+);", re.IGNORECASE | re.MULTILINE)
_CIPHERS_RE = re.compile(r"^\s*ssl_ciphers\s+(.+);", re.IGNORECASE | re.MULTILINE)


class FsConfNginx(Probe):
    id = "fs.conf.nginx"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/nginx/nginx.conf"),
            Path("/etc/nginx/sites-enabled"),
            Path("/etc/nginx/conf.d"),
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
            for proto in m.group(1).strip().split():
                proto_canon = proto.upper()
                # TLSv1, TLSv1.1, SSLv2, SSLv3 are weak.
                if proto_canon in {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}:
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=proto_canon,
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"nginx ssl_protocols enables {proto}",
                        evidence={"path": str(path), "directive": "ssl_protocols"},
                        remediation={"snippet": "ssl_protocols TLSv1.2 TLSv1.3;"},
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
                        title=f"nginx ssl_ciphers includes {token}",
                        evidence={
                            "path": str(path),
                            "directive": "ssl_ciphers",
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
