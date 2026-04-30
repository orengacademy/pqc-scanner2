from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._ssh_parser import parse_paths


class FsConfSshd(Probe):
    """Filesystem-roots variant of sshd_config scanner.

    Covers split-config layouts like /etc/ssh/sshd_config.d/*.conf and
    user-supplied paths via ScanContext.scan_paths.
    """
    id = "fs.conf.sshd"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:ssh", "bukukerja:ssh", "mykripto:ssh")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/ssh/sshd_config.d"),
            Path("/etc/ssh/ssh_config.d"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        files: list[Path] = []
        for root in self.roots:
            if not root.exists():
                continue
            if root.is_file():
                files.append(root)
            else:
                files.extend(p for p in root.rglob("*.conf") if p.is_file())
        for finding in parse_paths(files, self.id):
            emit(finding)
