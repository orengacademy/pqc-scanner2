"""app.spring.properties — Spring Boot crypto / TLS settings."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for


_SSL_PROTOCOLS_RE = re.compile(
    r"^\s*server\.ssl\.enabled-protocols\s*[=:]\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_SSL_CIPHERS_RE = re.compile(
    r"^\s*server\.ssl\.ciphers\s*[=:]\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_KEYSTORE_TYPE_RE = re.compile(
    r"^\s*server\.ssl\.key-store-type\s*[=:]\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


class AppSpringProperties(Probe):
    id = "app.spring.properties"
    family = ProbeFamily.APP
    framework_tags = ("nist-ir-8547:tls", "bukukerja:tls", "mykripto:tls")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            patterns = ("application.properties", "application.yml", "application.yaml",
                        "application-*.properties", "application-*.yml")
            for pat in patterns:
                for path in root.rglob(pat):
                    self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _SSL_PROTOCOLS_RE.finditer(text):
            for proto in re.split(r"[,\s]+", m.group(1).strip()):
                proto_canon = proto.upper().replace("V", "V")
                if proto_canon in {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}:
                    line_no = text[: m.start()].count("\n") + 1
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=proto_canon,
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=f"Spring server.ssl.enabled-protocols={proto} in {path.name}:{line_no}",
                        evidence={"path": str(path), "line": line_no, "protocol": proto},
                    ))
        for m in _SSL_CIPHERS_RE.finditer(text):
            cipher_str = m.group(1).strip()
            for token in re.split(r"[,:\s]+", cipher_str):
                if not token:
                    continue
                cls = classify(token)
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    line_no = text[: m.start()].count("\n") + 1
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=normalise(token),
                        classification=cls, severity=sev_for(cls),
                        title=f"Spring server.ssl.ciphers includes {token} in {path.name}:{line_no}",
                        evidence={"path": str(path), "line": line_no, "token": token},
                    ))
        for m in _KEYSTORE_TYPE_RE.finditer(text):
            ks_type = m.group(1).strip().upper()
            if ks_type == "JKS":
                line_no = text[: m.start()].count("\n") + 1
                emit(Finding(
                    probe_id=self.id,
                    algorithm="JKS",
                    classification=Classification.TINGGI,
                    severity=Severity.MED,
                    title=f"Spring keystore-type=JKS (deprecated) in {path.name}:{line_no}",
                    evidence={"path": str(path), "line": line_no},
                    remediation={"snippet": "server.ssl.key-store-type=PKCS12"},
                ))
