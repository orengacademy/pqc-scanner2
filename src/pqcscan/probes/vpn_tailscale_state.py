"""vpn.tailscale.state — flag presence of Tailscale (WireGuard underneath, Curve25519)."""
from __future__ import annotations

import shutil
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class VpnTailscaleState(Probe):
    id = "vpn.tailscale.state"
    family = ProbeFamily.VPN
    framework_tags = ("nist-ir-8547:vpn", "bukukerja:vpn", "mykripto:vpn")

    def __init__(self, state_paths: list[Path] | None = None):
        self.state_paths = state_paths or [
            Path("/var/lib/tailscale/tailscaled.state"),
            Path("/var/lib/tailscale"),
            Path("/etc/default/tailscaled"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return (
            any(p.exists() for p in self.state_paths)
            or shutil.which("tailscale") is not None
            or shutil.which("tailscaled") is not None
        )

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        evidence: dict = {"detection": []}
        for p in self.state_paths:
            if p.exists():
                evidence["detection"].append(str(p))
        for binary in ("tailscale", "tailscaled"):
            located = shutil.which(binary)
            if located:
                evidence["detection"].append(located)
        if not evidence["detection"]:
            return
        emit(Finding(
            probe_id=self.id,
            algorithm="Curve25519",
            classification=Classification.TINGGI,
            severity=Severity.HIGH,
            title="Tailscale present (WireGuard / Curve25519 underneath)",
            evidence=evidence,
        ))
