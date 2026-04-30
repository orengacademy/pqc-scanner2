from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._ssh_parser import parse_paths


class HostSshClientConfig(Probe):
    id = "host.ssh.client_config"
    family = ProbeFamily.HOST
    framework_tags = ("nist-ir-8547:ssh", "bukukerja:ssh", "mykripto:ssh")

    def __init__(self, config_paths: list[Path] | None = None):
        if config_paths is not None:
            self.config_paths = config_paths
        else:
            home = Path.home()
            self.config_paths = [
                Path("/etc/ssh/ssh_config"),
                home / ".ssh" / "config",
            ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(p.exists() for p in self.config_paths)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for finding in parse_paths(self.config_paths, self.id):
            emit(finding)
