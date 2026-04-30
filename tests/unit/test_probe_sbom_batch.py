"""Smoke tests for Plan B batch 5 SBOM probes (rpm, apk, pip, npm, gomod)."""
import shutil
from pathlib import Path

import pytest

from pqcscan.probes._base import ScanContext
from pqcscan.probes.sbom_lang_gomod import SbomLangGomod
from pqcscan.probes.sbom_lang_npm import SbomLangNpm
from pqcscan.probes.sbom_lang_pip import SbomLangPip
from pqcscan.probes.sbom_os_apk import SbomOsApk
from pqcscan.probes.sbom_os_rpm import SbomOsRpm


@pytest.mark.asyncio
async def test_apk_parses_installed_db(tmp_path: Path):
    db = tmp_path / "installed"
    db.write_text(
        "C:Q1abcdef\nP:musl\nV:1.2.4-r1\nA:x86_64\nS:382\n\n"
        "C:Q1xyz\nP:libcrypto3\nV:3.0.10-r0\n"
    )
    found = []
    probe = SbomOsApk(db_path=db)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("musl" in t for t in titles)
    assert any("libcrypto3" in t for t in titles)


@pytest.mark.asyncio
async def test_npm_parses_package_json(tmp_path: Path):
    pkg = tmp_path / "myapp" / "package.json"
    pkg.parent.mkdir()
    pkg.write_text('{"name":"myapp","version":"1.2.3","dependencies":{}}')
    found = []
    probe = SbomLangNpm(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("myapp" in t and "1.2.3" in t for t in titles)


@pytest.mark.asyncio
async def test_gomod_parses_module_and_requires(tmp_path: Path):
    g = tmp_path / "go.mod"
    g.write_text(
        "module github.com/orengacademy/example\n\n"
        "go 1.22\n\n"
        "require (\n"
        "    github.com/some/dep v1.4.5\n"
        "    golang.org/x/crypto v0.20.0\n"
        ")\n"
    )
    found = []
    probe = SbomLangGomod(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("github.com/orengacademy/example" in t for t in titles)
    assert any("golang.org/x/crypto" in t and "v0.20.0" in t for t in titles)


@pytest.mark.asyncio
async def test_pip_parses_dist_info(tmp_path: Path):
    distinfo = tmp_path / "exampledist-1.0.0.dist-info"
    distinfo.mkdir()
    (distinfo / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        "Name: exampledist\n"
        "Version: 1.0.0\n"
        "Summary: hello\n"
    )
    found = []
    probe = SbomLangPip(site_packages=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("exampledist" in t and "1.0.0" in t for t in titles)


@pytest.mark.asyncio
async def test_rpm_runs_when_present_or_skips():
    if shutil.which("rpm") is None:
        # Probe is harmless when rpm absent: applies() returns False.
        probe = SbomOsRpm()
        ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
        assert not await probe.applies(ctx)
        return
    # If rpm IS present, just run and accept any (or zero) findings.
    found = []
    probe = SbomOsRpm()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await probe.run(ctx, emit=lambda f: found.append(f))
    # No assertion on count — depends on host.
