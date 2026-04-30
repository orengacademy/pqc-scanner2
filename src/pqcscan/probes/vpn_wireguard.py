"""vpn.wireguard — flag WireGuard configs (Curve25519, Shor-vulnerable)."""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


class VpnWireguard(Probe):
    id = "vpn.wireguard"
    family = ProbeFamily.VPN
    framework_tags = ("nist-ir-8547:vpn", "bukukerja:vpn", "mykripto:vpn")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/wireguard"),
            Path("/etc/systemd/network"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            patterns = ("*.conf", "*.netdev")
            for pat in patterns:
                for path in root.rglob(pat):
                    if not path.is_file():
                        continue
                    try:
                        text = path.read_text(errors="replace")
                    except OSError:
                        continue
                    if "[Interface]" in text or "[Peer]" in text or "[WireGuard" in text:
                        emit(Finding(
                            probe_id=self.id,
                            algorithm="Curve25519",
                            classification=Classification.TINGGI,
                            severity=Severity.HIGH,
                            title=f"WireGuard config at {path} (uses Curve25519)",
                            evidence={
                                "path": str(path),
                                "note": ("WireGuard's Noise_IK handshake uses "
                                         "Curve25519 — Shor-vulnerable; PQC "
                                         "extensions not yet standard."),
                            },
                        ))
