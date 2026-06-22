"""vpn.wireguard — flag WireGuard configs (Curve25519, Shor-vulnerable)."""
from __future__ import annotations

from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


def _peer_psk_coverage(text: str) -> tuple[int, int]:
    """Count [Peer]/[WireGuardPeer] sections and how many set a PresharedKey.

    A PresharedKey mixes a symmetric secret into WireGuard's Noise_IK
    handshake; it is the only knob that gives a tunnel post-quantum hardening
    (a symmetric secret is not recoverable via Shor). Returns
    ``(peers_total, peers_with_psk)``.
    """
    peers_total = 0
    peers_with_psk = 0
    in_peer = False
    current_has_psk = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            if in_peer and current_has_psk:
                peers_with_psk += 1
            section = line[1:-1].strip().lower()
            in_peer = section in ("peer", "wireguardpeer")
            current_has_psk = False
            if in_peer:
                peers_total += 1
            continue
        # PresharedKey (.conf) and PresharedKeyFile (.netdev) both set a PSK.
        if in_peer and line.lower().replace(" ", "").startswith("presharedkey"):
            current_has_psk = True
    if in_peer and current_has_psk:
        peers_with_psk += 1
    return peers_total, peers_with_psk


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
                    if not ("[Interface]" in text or "[Peer]" in text
                            or "[WireGuard" in text):
                        continue

                    peers_total, peers_with_psk = _peer_psk_coverage(text)
                    if peers_total and peers_with_psk == peers_total:
                        # Every peer is PSK-hardened: key-agreement is still
                        # classical Curve25519, but harvested traffic is
                        # protected by the symmetric PSK -> downgrade.
                        classification = Classification.SEDERHANA
                        severity = Severity.MED
                        title = (f"WireGuard config at {path} (Curve25519 + "
                                 f"PresharedKey on all {peers_total} peer(s))")
                        note = ("Noise_IK uses Curve25519 (Shor-vulnerable), but "
                                "every peer sets a PresharedKey — the symmetric "
                                "PSK is mixed into the handshake and gives "
                                "post-quantum hardening against harvested traffic.")
                    elif peers_with_psk:
                        classification = Classification.TINGGI
                        severity = Severity.HIGH
                        title = (f"WireGuard config at {path} (Curve25519; "
                                 f"PresharedKey on {peers_with_psk}/{peers_total} "
                                 "peers)")
                        note = ("Noise_IK uses Curve25519 (Shor-vulnerable). Only "
                                "some peers set a PresharedKey; peers without one "
                                "have no post-quantum hardening.")
                    else:
                        classification = Classification.TINGGI
                        severity = Severity.HIGH
                        title = f"WireGuard config at {path} (uses Curve25519)"
                        note = ("Noise_IK uses Curve25519 — Shor-vulnerable; no "
                                "PresharedKey set, so no symmetric PQC hardening. "
                                "PQC extensions not yet standard.")

                    emit(Finding(
                        probe_id=self.id,
                        algorithm="Curve25519",
                        classification=classification,
                        severity=severity,
                        title=title,
                        evidence={
                            "path": str(path),
                            "peers": peers_total,
                            "peers_with_psk": peers_with_psk,
                            "note": note,
                        },
                    ))
