from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class FsConfOpensslCnf(Probe):
    """Scan arbitrary openssl.cnf-style files for an activated legacy provider."""
    id = "fs.conf.openssl_cnf"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("bukukerja:host", "mykripto:host")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/ssl"),
            Path("/etc/pki/tls"),
            Path("/usr/local/etc/openssl"),
            Path("/usr/local/etc/openssl@3"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            files = [root] if root.is_file() else list(root.rglob("*.cnf"))
            for path in files:
                if not path.is_file():
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
