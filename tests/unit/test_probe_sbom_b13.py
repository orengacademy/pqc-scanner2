"""Tests for B13 lang SBOM expansion."""
import shutil
import sys
from pathlib import Path

import pytest

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import ScanContext
from pqcscan.probes.sbom_lang_cargo import SbomLangCargo
from pqcscan.probes.sbom_lang_composer import SbomLangComposer
from pqcscan.probes.sbom_lang_maven import SbomLangMaven
from pqcscan.probes.sbom_os_brew import SbomOsBrew
from pqcscan.probes.sbom_os_pacman import SbomOsPacman
from pqcscan.probes.sbom_os_windows import SbomOsWindows


@pytest.mark.parametrize(
    "cls,probe_id",
    [
        (SbomOsPacman,    "sbom.os.pacman"),
        (SbomOsBrew,      "sbom.os.brew"),
        (SbomOsWindows,   "sbom.os.windows"),
        (SbomLangCargo,   "sbom.lang.cargo"),
        (SbomLangMaven,   "sbom.lang.maven"),
        (SbomLangComposer,"sbom.lang.composer"),
    ],
)
def test_metadata(cls, probe_id):
    p = cls()
    assert p.id == probe_id
    assert p.family is ProbeFamily.SBOM


@pytest.mark.asyncio
async def test_pacman_parses_local_db(tmp_path: Path):
    pkg = tmp_path / "vim-9.0.1234-1"
    pkg.mkdir()
    (pkg / "desc").write_text(
        "%NAME%\nvim\n\n%VERSION%\n9.0.1234-1\n\n%ARCH%\nx86_64\n"
    )
    found: list = []
    p = SbomOsPacman(db_root=tmp_path)
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("vim" in f.title for f in found)


@pytest.mark.asyncio
async def test_brew_skips_when_binary_absent():
    p = SbomOsBrew(brew_bin="/no/such/brew")
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_windows_skips_on_non_windows():
    if sys.platform == "win32":
        pytest.skip("Linux-only guard test")
    p = SbomOsWindows()
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    assert not await p.applies(ctx)


@pytest.mark.asyncio
async def test_cargo_parses_lockfile(tmp_path: Path):
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.197"\n\n'
        '[[package]]\nname = "tokio"\nversion = "1.36.0"\n'
    )
    found: list = []
    p = SbomLangCargo(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    titles = [f.title for f in found]
    assert any("serde" in t and "1.0.197" in t for t in titles)
    assert any("tokio" in t and "1.36.0" in t for t in titles)


@pytest.mark.asyncio
async def test_maven_parses_pom(tmp_path: Path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        "<project>\n<dependencies>\n"
        "  <dependency><groupId>org.springframework</groupId>"
        "<artifactId>spring-core</artifactId><version>6.1.4</version></dependency>\n"
        "</dependencies>\n</project>\n"
    )
    found: list = []
    p = SbomLangMaven(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("org.springframework:spring-core" in f.title and "6.1.4" in f.title
               for f in found)


@pytest.mark.asyncio
async def test_composer_parses_lock(tmp_path: Path):
    proj = tmp_path / "myapp"
    proj.mkdir()
    (proj / "composer.lock").write_text(
        '{"packages": [{"name": "monolog/monolog", "version": "3.5.0"}]}'
    )
    found: list = []
    p = SbomLangComposer(roots=[tmp_path])
    ctx = ScanContext(scan_id=1, mode="user", available_capabilities=set())
    await p.run(ctx, emit=lambda f: found.append(f))
    assert any("monolog/monolog" in f.title and "3.5.0" in f.title for f in found)
