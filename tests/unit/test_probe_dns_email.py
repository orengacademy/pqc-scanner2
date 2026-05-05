"""Tests for B12 DNS/email/web-auth probes."""
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.dns_dnssec_zones import DnsDnssecZones
from pqcscan.probes.email_dkim_selectors import EmailDkimSelectors
from pqcscan.probes.email_smime_certs import EmailSmimeCerts
from pqcscan.probes.trust_system_roots import TrustSystemRoots
from pqcscan.probes.web_webauthn_config import WebWebauthnConfig


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (DnsDnssecZones,    "dns.dnssec.zones"),
        (EmailDkimSelectors, "email.dkim.selectors"),
        (EmailSmimeCerts,   "email.smime.certs"),
        (WebWebauthnConfig, "web.webauthn.config"),
        (TrustSystemRoots,  "trust.system_roots"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.DNS_EMAIL


@pytest.mark.asyncio
async def test_dnssec_flags_rsasha1_in_zone_dnskey(tmp_path: Path):
    z = tmp_path / "example.zone"
    # Algorithm 5 = RSASHA1 (deprecated)
    z.write_text(
        "example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 7200 3600 1209600 3600\n"
        "example.com. 3600 IN DNSKEY 256 3 5 AwEAAdHoNTOWgPZSv...\n"
    )
    found: list = []
    p = DnsDnssecZones(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    deprecated = [f for f in found if f.classification is Classification.SANGAT_TINGGI]
    assert deprecated


@pytest.mark.asyncio
async def test_dnssec_flags_policy_directive(tmp_path: Path):
    cfg = tmp_path / "named.conf"
    cfg.write_text("dnssec-policy default { keys { ksk lifetime 0 algorithm rsasha256; }; };\n")
    found: list = []
    p = DnsDnssecZones(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("RSASHA256" in f.algorithm for f in found)


@pytest.mark.asyncio
async def test_dkim_txt_record_short_key(tmp_path: Path):
    txt = tmp_path / "selector1._domainkey.txt"
    # 100 chars of base64 ~ 600 bits — well under 2048 -> Sangat-Tinggi
    short = "A" * 100
    txt.write_text(f"v=DKIM1; k=rsa; p={short}")
    found: list = []
    p = EmailDkimSelectors(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any(f.classification is Classification.SANGAT_TINGGI for f in found)


@pytest.mark.asyncio
async def test_webauthn_config_detects_rp_id(tmp_path: Path):
    cfg = tmp_path / "webauthn.yaml"
    cfg.write_text("rp_id: example.com\n")
    found: list = []
    p = WebWebauthnConfig(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("relying-party" in t for t in titles)


@pytest.mark.asyncio
async def test_webauthn_config_flags_rs256_algs(tmp_path: Path):
    cfg = tmp_path / "webauthn.properties"
    cfg.write_text("webauthn_algorithms = RS256, ES256\n")
    found: list = []
    p = WebWebauthnConfig(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("WebAuthn algorithms" in t for t in titles)


@pytest.mark.asyncio
async def test_trust_system_roots_uses_bundle_path(tmp_path: Path):
    # Generate an RSA-2048 self-signed cert acting as a "root" for the test.
    import shutil
    import subprocess
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    key = tmp_path / "k.pem"
    cert = tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=test-root"],
        check=True, capture_output=True,
    )
    # Build a "bundle" with the single cert.
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_bytes(cert.read_bytes())
    found: list = []
    p = TrustSystemRoots(bundle_paths=(bundle,))
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    rsa_findings = [f for f in found if f.algorithm.startswith("RSA-")]
    assert rsa_findings
    assert all(f.classification is Classification.SANGAT_TINGGI for f in rsa_findings)
