"""Tests for FOSS-tool integration probes — Syft, Semgrep."""
import shutil
from pathlib import Path

import pytest

from pqcscan.core.types import Classification, ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.code_semgrep_pqc import CodeSemgrepPqc
from pqcscan.probes.sbom_syft import SbomSyft


@pytest.mark.parametrize(
    "cls,probe_id,family",
    [
        (SbomSyft,        "sbom.syft",        ProbeFamily.SBOM),
        (CodeSemgrepPqc,  "code.semgrep.pqc", ProbeFamily.CODE),
    ],
)
def test_metadata(cls, probe_id, family):
    p = cls()
    assert p.id == probe_id
    assert p.family is family


@pytest.mark.asyncio
async def test_syft_skips_when_binary_absent():
    p = SbomSyft(syft_bin="/no/such/syft")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_semgrep_skips_when_binary_absent(tmp_path: Path):
    p = CodeSemgrepPqc(roots=[tmp_path], semgrep_bin="/no/such/semgrep")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_semgrep_runs_against_sample_when_binary_present(tmp_path: Path):
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep binary not available on test host")
    sample = tmp_path / "weak.py"
    sample.write_text(
        "import hashlib\n"
        "h = hashlib.md5(b'abc').hexdigest()\n"
    )
    found: list = []
    p = CodeSemgrepPqc(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert all(f.classification == Classification.SANGAT_TINGGI for f in found)
