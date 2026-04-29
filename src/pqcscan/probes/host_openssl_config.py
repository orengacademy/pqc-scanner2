from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_DEFAULT_PATHS = [
    Path("/etc/ssl/openssl.cnf"),
    Path("/etc/pki/tls/openssl.cnf"),
    Path("/usr/local/etc/openssl/openssl.cnf"),
    Path("/usr/local/etc/openssl@3/openssl.cnf"),
]


class HostOpenSSLConfig(Probe):
    id = "host.openssl.config"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:host", "bukukerja:host", "mykripto:host")

    def __init__(self, config_paths: list[Path] | None = None):
        self.config_paths = config_paths if config_paths is not None else _DEFAULT_PATHS

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.config_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for path in self.config_paths:
            if not path.exists():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            self._scan_text(text, path, emit)

    def _scan_text(self, text: str, path: Path, emit: Emitter) -> None:
        if re.search(r"^\s*legacy\s*=\s*legacy_sect", text, re.MULTILINE):
            if re.search(r"\[legacy_sect\][^\[]*activate\s*=\s*1", text, re.DOTALL):
                emit(Finding(
                    probe_id=self.id,
                    algorithm="MD5/RC4/etc-via-legacy-provider",
                    classification=Classification.SANGAT_TINGGI,
                    severity=Severity.HIGH,
                    title=f"OpenSSL legacy provider activated in {path}",
                    evidence={"path": str(path), "section": "legacy_sect"},
                    remediation={
                        "snippet": "# Comment out 'legacy = legacy_sect' or set activate = 0",
                    },
                ))
