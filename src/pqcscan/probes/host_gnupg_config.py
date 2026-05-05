from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_GPG_DIRECTIVES = (
    "personal-cipher-preferences",
    "personal-digest-preferences",
    "personal-compress-preferences",
    "default-preference-list",
    "cert-digest-algo",
)


class HostGnupgConfig(Probe):
    id = "host.gnupg.config"
    family = ProbeFamily.HOST
    framework_tags = ("bukukerja:host", "mykripto:host")

    def __init__(self, config_paths: list[Path] | None = None):
        if config_paths is not None:
            self.config_paths = config_paths
        else:
            home = Path.home()
            self.config_paths = [
                home / ".gnupg" / "gpg.conf",
                Path("/etc/gnupg/gpg.conf"),
            ]

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
        for line_no, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            for directive in _GPG_DIRECTIVES:
                m = re.match(rf"^{directive}\s+(.+)$", line, re.IGNORECASE)
                if not m:
                    continue
                values = m.group(1).strip()
                tokens = re.split(r"[,\s]+", values)
                for token in tokens:
                    if not token:
                        continue
                    cls = classify(token)
                    if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                        emit(Finding(
                            probe_id=self.id,
                            algorithm=normalise(token),
                            classification=cls,
                            severity=_sev(cls),
                            title=f"gpg.conf {directive} prefers {token}",
                            evidence={
                                "path": str(path),
                                "line": line_no,
                                "directive": directive,
                                "token": token,
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
