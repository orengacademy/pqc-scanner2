"""Smoke tests for the FOSS VA-suite probes.

Each probe is a thin wrapper around an external binary. On the test host most
of those binaries are absent, so we mainly assert metadata + applies()=False
behaviour. Branch coverage of the parsers themselves runs in real-target
fixtures (out of scope for this batch).
"""
import pytest

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_bandit import CodeBandit
from pqcscan.probes.cve_cargo_audit import CveCargoAudit
from pqcscan.probes.cve_govulncheck import CveGovulncheck
from pqcscan.probes.cve_npm_audit import CveNpmAudit
from pqcscan.probes.cve_pip_audit import CvePipAudit
from pqcscan.probes.cve_trivy_fs import CveTrivyFs
from pqcscan.probes.host_lynis import HostLynis
from pqcscan.probes.net_tls_nmap_ssl import NetTlsNmapSsl
from pqcscan.probes.net_tls_sslyze import NetTlsSslyze
from pqcscan.probes.net_tls_testssl import NetTlsTestssl
from pqcscan.probes.secrets_gitleaks import SecretsGitleaks


@pytest.mark.parametrize(
    "cls,probe_id,family",
    [
        (NetTlsTestssl,   "net.tls.testssl",   ProbeFamily.NETWORK),
        (NetTlsSslyze,    "net.tls.sslyze",    ProbeFamily.NETWORK),
        (NetTlsNmapSsl,   "net.tls.nmap_ssl",  ProbeFamily.NETWORK),
        (CvePipAudit,     "cve.pip_audit",     ProbeFamily.SBOM),
        (CveNpmAudit,     "cve.npm_audit",     ProbeFamily.SBOM),
        (CveGovulncheck,  "cve.govulncheck",   ProbeFamily.SBOM),
        (CveCargoAudit,   "cve.cargo_audit",   ProbeFamily.SBOM),
        (CveTrivyFs,      "cve.trivy_fs",      ProbeFamily.SBOM),
        (HostLynis,       "host.lynis",        ProbeFamily.HOST),
        (CodeBandit,      "code.bandit",       ProbeFamily.CODE),
        (SecretsGitleaks, "secrets.gitleaks",  ProbeFamily.SECRETS),
    ],
)
def test_metadata(cls, probe_id, family):
    p = cls()
    assert p.id == probe_id
    assert p.family is family


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls,bin_kwarg",
    [
        (NetTlsTestssl,   {"testssl_bin": "/no/such/testssl"}),
        (NetTlsSslyze,    {"sslyze_bin":  "/no/such/sslyze"}),
        (NetTlsNmapSsl,   {"nmap_bin":    "/no/such/nmap"}),
        (CvePipAudit,     {"pip_audit_bin": "/no/such/pip-audit"}),
        (CveTrivyFs,      {"trivy_bin":   "/no/such/trivy"}),
        (CveCargoAudit,   {"cargo_bin":   "/no/such/cargo"}),
    ],
)
async def test_skips_when_binary_absent(cls, bin_kwarg):
    p = cls(**bin_kwarg)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_lynis_requires_root():
    p = HostLynis()
    # User mode with empty caps → applies()=False even if lynis is on PATH.
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)
