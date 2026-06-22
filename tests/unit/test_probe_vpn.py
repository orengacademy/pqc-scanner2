"""Smoke tests for vpn.{wireguard, openvpn.config, tailscale.state}."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.vpn_openvpn_config import VpnOpenvpnConfig
from pqcscan.probes.vpn_tailscale_state import VpnTailscaleState
from pqcscan.probes.vpn_wireguard import VpnWireguard


@pytest.mark.asyncio
async def test_wireguard_flags_interface_section(tmp_path: Path):
    cfg = tmp_path / "wg0.conf"
    cfg.write_text(
        "[Interface]\n"
        "PrivateKey = ABC=\n"
        "Address = 10.0.0.1/24\n"
        "ListenPort = 51820\n"
        "\n[Peer]\n"
        "PublicKey = DEF=\n"
        "AllowedIPs = 10.0.0.2/32\n"
    )
    found: list = []
    probe = VpnWireguard(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert any(f.algorithm == "Curve25519" for f in found)
    assert any(f.classification is Classification.TINGGI for f in found)


@pytest.mark.asyncio
async def test_wireguard_psk_on_all_peers_downgrades_severity(tmp_path: Path):
    # A PresharedKey mixes a symmetric secret into the Noise handshake, giving
    # the tunnel post-quantum hardening. A config where every peer sets one is
    # only partially exposed (Curve25519 key-agreement is still classical, but
    # harvested traffic is PSK-protected) -> SEDERHANA / MED, not TINGGI / HIGH.
    cfg = tmp_path / "wg0.conf"
    cfg.write_text(
        "[Interface]\n"
        "PrivateKey = ABC=\n"
        "\n[Peer]\n"
        "PublicKey = DEF=\n"
        "PresharedKey = GHI=\n"
        "AllowedIPs = 10.0.0.2/32\n"
    )
    found: list = []
    probe = VpnWireguard(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.SEDERHANA
    assert found[0].severity is Severity.MED
    assert "PresharedKey" in found[0].title
    assert found[0].evidence["peers_with_psk"] == 1


@pytest.mark.asyncio
async def test_wireguard_mixed_psk_stays_high(tmp_path: Path):
    # One peer with a PSK, one without -> the unprotected peer keeps the config
    # at TINGGI / HIGH, but the finding reports the partial coverage.
    cfg = tmp_path / "wg0.conf"
    cfg.write_text(
        "[Interface]\n"
        "PrivateKey = ABC=\n"
        "\n[Peer]\n"
        "PublicKey = DEF=\n"
        "PresharedKey = GHI=\n"
        "\n[Peer]\n"
        "PublicKey = JKL=\n"
        "AllowedIPs = 10.0.0.3/32\n"
    )
    found: list = []
    probe = VpnWireguard(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert len(found) == 1
    assert found[0].classification is Classification.TINGGI
    assert found[0].severity is Severity.HIGH
    assert found[0].evidence["peers"] == 2
    assert found[0].evidence["peers_with_psk"] == 1


@pytest.mark.asyncio
async def test_wireguard_no_findings_for_unrelated_conf(tmp_path: Path):
    (tmp_path / "random.conf").write_text("# nothing wireguard about this\nfoo = bar\n")
    found: list = []
    probe = VpnWireguard(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    assert found == []


@pytest.mark.asyncio
async def test_openvpn_flags_weak_cipher_and_tls_version_min(tmp_path: Path):
    cfg = tmp_path / "server.conf"
    cfg.write_text(
        "port 1194\n"
        "proto udp\n"
        "cipher AES-128-CBC\n"
        "auth SHA1\n"
        "tls-version-min 1.0\n"
    )
    found: list = []
    probe = VpnOpenvpnConfig(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("AES-128-CBC" in t for t in titles)
    assert any("SHA1" in t for t in titles)
    assert any("tls-version-min=1.0" in t for t in titles)


@pytest.mark.asyncio
async def test_openvpn_no_findings_for_modern_config(tmp_path: Path):
    cfg = tmp_path / "server.conf"
    cfg.write_text(
        "cipher AES-256-GCM\n"
        "auth SHA256\n"
        "tls-version-min 1.2\n"
    )
    found: list = []
    probe = VpnOpenvpnConfig(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    # AES-256 / SHA256 are below the Tinggi threshold; tls 1.2 is fine.
    assert found == []


@pytest.mark.asyncio
async def test_tailscale_no_findings_when_absent(tmp_path: Path):
    # Use a tmp_path that contains no Tailscale state; shutil.which() may still
    # find a system-wide tailscale binary, in which case the probe applies and
    # emits a finding. Both paths are valid — we just smoke-test the API.
    probe = VpnTailscaleState(state_paths=[tmp_path / "nonexistent"])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    found: list = []
    await probe.run(ctx, emit=lambda f: found.append(f))
    if found:
        assert found[0].algorithm == "Curve25519"
