"""Tests for B11 signing/integrity probes."""
import shutil
import sys

import pytest

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.sign_code_authenticode import SignCodeAuthenticode
from pqcscan.probes.sign_git_signing_keys import SignGitSigningKeys
from pqcscan.probes.sign_gpg_keyrings import SignGpgKeyrings
from pqcscan.probes.sign_image_cosign import SignImageCosign
from pqcscan.probes.sign_repo_aptdnf_keys import SignRepoAptdnfKeys


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (SignGpgKeyrings,      "sign.gpg.keyrings"),
        (SignRepoAptdnfKeys,   "sign.repo.aptdnf_keys"),
        (SignCodeAuthenticode, "sign.code.authenticode"),
        (SignGitSigningKeys,   "sign.git.signing_keys"),
        (SignImageCosign,      "sign.image.cosign"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.SIGN


@pytest.mark.asyncio
async def test_gpg_skips_when_binary_absent():
    p = SignGpgKeyrings(gpg_bin="/no/such/gpg")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_authenticode_skips_on_non_windows():
    if sys.platform == "win32":
        pytest.skip("Linux-only guard test")
    p = SignCodeAuthenticode()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_cosign_applies_only_when_binary_present():
    p = SignImageCosign()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    expected = shutil.which("cosign") is not None
    assert (await p.applies(ctx)) is expected


@pytest.mark.asyncio
async def test_git_signing_applies_only_with_git():
    p = SignGitSigningKeys()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    expected = shutil.which("git") is not None
    assert (await p.applies(ctx)) is expected
