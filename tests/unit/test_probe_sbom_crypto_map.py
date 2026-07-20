"""Tests for sbom.crypto_map (SBOM -> crypto-primitive mapping)."""
from pathlib import Path

from pqcscan.core.types import Classification, Finding, Severity
from pqcscan.probes._base import ScanContext
from pqcscan.probes.sbom_crypto_map import CRYPTO_LIBRARY_MAP, SbomCryptoMap


def _ctx(paths: list[Path] | None = None) -> ScanContext:
    return ScanContext(scan_id=1, mode="user", available_capabilities=set(),
                       scan_paths=paths or [])


async def _run(root: Path) -> list[Finding]:
    found: list[Finding] = []
    probe = SbomCryptoMap(roots=[root])
    await probe.run(_ctx(), emit=found.append)
    return found


def _by_purl(found: list[Finding]) -> dict[str, Finding]:
    return {f.algorithm: f for f in found}


async def test_requirements_classical_and_pqc(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "cryptography==41.0.0\n"
        "pqcrypto>=0.3\n"
        "# a comment\n"
        "some-unknown-lib==1.0\n"
    )
    found = await _run(tmp_path)
    by = _by_purl(found)
    assert "pkg:pypi/cryptography" in by
    assert by["pkg:pypi/cryptography"].classification is Classification.TINGGI
    assert by["pkg:pypi/cryptography"].severity is Severity.HIGH
    assert by["pkg:pypi/cryptography"].evidence["version"] == "41.0.0"
    assert by["pkg:pypi/cryptography"].evidence["ecosystem"] == "pypi"
    assert "pkg:pypi/pqcrypto" in by
    assert by["pkg:pypi/pqcrypto"].classification is Classification.PQC_READY
    assert by["pkg:pypi/pqcrypto"].severity is Severity.INFO
    # unknown dep must not be flagged
    assert "pkg:pypi/some-unknown-lib" not in by
    assert len(found) == 2


async def test_package_json_flags_crypto_js(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"name": "app", "dependencies": {"crypto-js": "^4.1.1", "left-pad": "1.3.0"}}'
    )
    found = await _run(tmp_path)
    by = _by_purl(found)
    assert "pkg:npm/crypto-js" in by
    assert by["pkg:npm/crypto-js"].classification is Classification.TINGGI
    assert by["pkg:npm/crypto-js"].evidence["version"] == "^4.1.1"
    assert len(found) == 1


async def test_cargo_toml_classical_and_pqc(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "demo"\n\n'
        '[dependencies]\n'
        'ed25519-dalek = "2.1"\n'
        'pqcrypto = { version = "0.17" }\n'
        'serde = "1.0"\n'
    )
    found = await _run(tmp_path)
    by = _by_purl(found)
    assert by["pkg:cargo/ed25519-dalek"].classification is Classification.TINGGI
    assert by["pkg:cargo/ed25519-dalek"].evidence["version"] == "2.1"
    assert by["pkg:cargo/pqcrypto"].classification is Classification.PQC_READY
    assert by["pkg:cargo/pqcrypto"].evidence["version"] == "0.17"
    assert "pkg:cargo/serde" not in by
    assert len(found) == 2


async def test_go_mod_and_maven(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.21\n\n"
        "require (\n"
        "\tgolang.org/x/crypto v0.17.0\n"
        "\tgithub.com/cloudflare/circl v1.3.7\n"
        "\tgithub.com/some/unknown v1.0.0\n"
        ")\n"
    )
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<dependencies>"
        "<dependency><groupId>org.bouncycastle</groupId>"
        "<artifactId>bcprov-jdk18on</artifactId><version>1.77</version></dependency>"
        "<dependency><groupId>org.bouncycastle</groupId>"
        "<artifactId>bcpqc-jdk18on</artifactId><version>1.77</version></dependency>"
        "</dependencies></project>"
    )
    found = await _run(tmp_path)
    by = _by_purl(found)
    assert by["pkg:golang/golang.org/x/crypto"].classification is Classification.TINGGI
    assert by["pkg:golang/github.com/cloudflare/circl"].classification is Classification.PQC_READY
    # maven artifactId prefix match with a JDK-variant suffix
    assert by["pkg:maven/bcprov-jdk18on"].classification is Classification.TINGGI
    assert by["pkg:maven/bcpqc-jdk18on"].classification is Classification.PQC_READY


async def test_pyproject_deps(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n'
        'dependencies = ["pynacl>=1.5", "requests>=2"]\n'
    )
    found = await _run(tmp_path)
    by = _by_purl(found)
    assert by["pkg:pypi/pynacl"].classification is Classification.TINGGI
    assert "pkg:pypi/requests" not in by


async def test_unknown_only_manifest_no_findings(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0\n")
    found = await _run(tmp_path)
    assert found == []


async def test_missing_path_applies_false_no_crash(tmp_path: Path):
    missing = tmp_path / "does-not-exist"
    probe = SbomCryptoMap(roots=[missing])
    found: list[Finding] = []
    await probe.run(_ctx(), emit=found.append)
    assert found == []
    # applies keys off ctx.scan_paths
    assert await probe.applies(_ctx()) is False
    assert await probe.applies(_ctx([tmp_path])) is True


async def test_malformed_manifest_is_guarded(tmp_path: Path):
    (tmp_path / "package.json").write_text("{ this is not valid json ")
    (tmp_path / "Cargo.toml").write_text("[dependencies\nbroken = ")
    found = await _run(tmp_path)
    assert found == []


def test_corpus_is_curated_and_multi_ecosystem():
    total = sum(len(v) for v in CRYPTO_LIBRARY_MAP.values())
    assert total >= 30
    assert set(CRYPTO_LIBRARY_MAP) == {"pypi", "npm", "golang", "cargo", "maven"}
