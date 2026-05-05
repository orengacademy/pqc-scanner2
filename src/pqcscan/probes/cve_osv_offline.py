"""cve.osv_offline — match Python deps against an OSV.dev snapshot.

When an OSV snapshot is present (path resolved from constructor arg →
``$PQCSCAN_OSV_SNAPSHOT`` env var → ``/var/lib/pqcscan/osv-snapshot.jsonl``
default), this probe walks ``roots`` for ``requirements.txt`` files,
parses ``name==version`` style declarations, and emits one finding per
matching advisory.

When no snapshot is configured, the probe emits the original deferral
notice so the registry stays self-documenting.

Snapshot format: JSONL (one OSV record per line) or a JSON array of
records. OSV record schema (subset we use):
    {"id": "GHSA-xxxx", "summary": "...",
     "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                   "ranges": [...]}],
     "severity": [...]}
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DEFAULT_SNAPSHOT = Path("/var/lib/pqcscan/osv-snapshot.jsonl")
_ENV_SNAPSHOT = "PQCSCAN_OSV_SNAPSHOT"

# Capture the full PEP 508 constraint per requirements.txt line:
#   name<extras>?<spec>?<;markers>?
# Group 1 = name, group 2 = comma-separated specifier list (or empty).
_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)"      # package name
    r"(?:\[[^\]]+\])?"                         # extras (ignored)
    r"\s*((?:(?:==|>=|<=|~=|!=|===|>|<)\s*[A-Za-z0-9._+!*-]+\s*,?\s*)*)"
    r"(?:\s*;.*)?$",                          # markers (ignored)
    re.MULTILINE,
)
# Cargo.lock blocks: [[package]] / name = "..." / version = "..."
_CARGO_PACKAGE_RE = re.compile(
    r'\[\[package\]\]\s*\n\s*name\s*=\s*"([^"]+)"\s*\n\s*'
    r'version\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
# poetry.lock uses the same [[package]] TOML shape as Cargo.lock.
_POETRY_PACKAGE_RE = _CARGO_PACKAGE_RE
# go.sum: "<module> <version>[/go.mod] h1:<hash>"
_GO_SUM_LINE_RE = re.compile(
    r"^(\S+)\s+(v\S+?)(?:/go\.mod)?\s+h1:",
    re.MULTILINE,
)
# Gemfile.lock specs: "    <name> (<version>)"
_GEMFILE_SPEC_RE = re.compile(
    r"^[ \t]+([A-Za-z0-9][A-Za-z0-9._-]*)\s+\(([^)]+)\)\s*$",
    re.MULTILINE,
)
# mix.lock entries: "<name>": {:hex, :<name>, "<version>",
_MIX_LOCK_RE = re.compile(
    r'"([A-Za-z0-9_][A-Za-z0-9._-]*)":\s*\{:hex,\s*:[A-Za-z0-9_]+,\s*'
    r'"([^"]+)"',
)
# gradle.lockfile lines: "group:artifact:version=configs"
_GRADLE_LOCK_LINE_RE = re.compile(
    r"^([A-Za-z0-9._-]+):([A-Za-z0-9._-]+):([A-Za-z0-9._+-]+)=",
    re.MULTILINE,
)
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
                 "vendor"}


class CveOsvOffline(Probe):
    id = "cve.osv_offline"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:cve", "mykripto:cve")

    def __init__(
        self,
        snapshot_path: Path | str | None = None,
        roots: list[Path] | None = None,
    ):
        self.snapshot_path = snapshot_path
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    def _resolve_snapshot(self) -> Path:
        if self.snapshot_path:
            return Path(self.snapshot_path)
        env = os.environ.get(_ENV_SNAPSHOT)
        if env:
            return Path(env)
        return _DEFAULT_SNAPSHOT

    async def applies(self, ctx: ScanContext) -> bool:
        return True  # always — emits either a deferral or real findings

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        snap = self._resolve_snapshot()
        if not snap.is_file():
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=("OSV.dev offline CVE matching not yet implemented; "
                       "use cve.grype for online vuln data"),
                evidence={"deferred_to":
                          "Plan F — PyInstaller offline pack with "
                          "OSV.dev snapshot"},
            ))
            return

        index = _load_snapshot_index(snap)
        if not index:
            emit(Finding(
                probe_id=self.id, algorithm="N/A",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"OSV snapshot at {snap} loaded 0 records",
                evidence={"snapshot": str(snap)},
            ))
            return

        emit(Finding(
            probe_id=self.id, algorithm="N/A",
            classification=Classification.INFO, severity=Severity.INFO,
            title=(f"OSV snapshot loaded: "
                   f"{sum(len(v) for v in index.values())} advisories "
                   f"across {len(index)} packages"),
            evidence={"snapshot": str(snap),
                      "package_count": len(index)},
        ))

        for root in self.roots:
            if not root.exists():
                continue
            for req in (root.rglob("requirements.txt") if root.is_dir()
                        else []):
                if any(part in _EXCLUDE_DIRS for part in req.parts):
                    continue
                self._scan_requirements(req, index, emit)
            for lock in (root.rglob("package-lock.json") if root.is_dir()
                         else []):
                if any(part in _EXCLUDE_DIRS for part in lock.parts):
                    continue
                self._scan_npm_lockfile(lock, index, emit)
            for cargo in (root.rglob("Cargo.lock") if root.is_dir()
                          else []):
                if any(part in _EXCLUDE_DIRS for part in cargo.parts):
                    continue
                self._scan_cargo_lock(cargo, index, emit)
            for gosum in (root.rglob("go.sum") if root.is_dir() else []):
                if any(part in _EXCLUDE_DIRS for part in gosum.parts):
                    continue
                self._scan_go_sum(gosum, index, emit)
            for pipf in (root.rglob("Pipfile.lock") if root.is_dir() else []):
                if any(part in _EXCLUDE_DIRS for part in pipf.parts):
                    continue
                self._scan_pipfile_lock(pipf, index, emit)
            for poetry in (root.rglob("poetry.lock") if root.is_dir()
                           else []):
                if any(part in _EXCLUDE_DIRS for part in poetry.parts):
                    continue
                self._scan_poetry_lock(poetry, index, emit)
            for composer in (root.rglob("composer.lock") if root.is_dir()
                             else []):
                if any(part in _EXCLUDE_DIRS for part in composer.parts):
                    continue
                self._scan_composer_lock(composer, index, emit)
            for gemfile in (root.rglob("Gemfile.lock") if root.is_dir()
                            else []):
                if any(part in _EXCLUDE_DIRS for part in gemfile.parts):
                    continue
                self._scan_gemfile_lock(gemfile, index, emit)
            for nuget in (root.rglob("packages.lock.json") if root.is_dir()
                          else []):
                if any(part in _EXCLUDE_DIRS for part in nuget.parts):
                    continue
                self._scan_nuget_lock(nuget, index, emit)
            for mix in (root.rglob("mix.lock") if root.is_dir() else []):
                if any(part in _EXCLUDE_DIRS for part in mix.parts):
                    continue
                self._scan_mix_lock(mix, index, emit)
            for pub in (root.rglob("pubspec.lock") if root.is_dir() else []):
                if any(part in _EXCLUDE_DIRS for part in pub.parts):
                    continue
                self._scan_pub_lock(pub, index, emit)
            for gradle in (root.rglob("gradle.lockfile") if root.is_dir()
                           else []):
                if any(part in _EXCLUDE_DIRS for part in gradle.parts):
                    continue
                self._scan_gradle_lockfile(gradle, index, emit)

    def _scan_requirements(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _REQ_LINE_RE.finditer(text):
            name = m.group(1)
            spec_str = (m.group(2) or "").strip().rstrip(",").strip()
            line_no = text[: m.start()].count("\n") + 1
            key = ("pypi", name.lower())
            advisories = index.get(key, [])
            if not advisories:
                continue
            for adv in advisories:
                exact_match = _spec_is_exact_pin(spec_str)
                hit, sample = _advisory_matches_specifier(spec_str, adv)
                if not hit:
                    continue
                if exact_match:
                    cls, sev, qualifier = (
                        Classification.TINGGI, Severity.HIGH, "==",
                    )
                else:
                    # Range overlap → "potentially affected".
                    cls, sev, qualifier = (
                        Classification.SEDERHANA, Severity.MED, "range",
                    )
                emit(Finding(
                    probe_id=self.id,
                    algorithm=adv.get("id", "N/A"),
                    classification=cls, severity=sev,
                    title=(f"{adv.get('id', '?')} affects "
                           f"{name}{spec_str or ''} ({qualifier} {sample}) "
                           f"in {path.name}:{line_no}"),
                    evidence={
                        "advisory_id": adv.get("id", ""),
                        "package": name,
                        "constraint": spec_str,
                        "sample_affected_version": sample,
                        "match_kind": qualifier,
                        "summary": (adv.get("summary") or "")[:200],
                        "path": str(path), "line": line_no,
                        "ecosystem": "PyPI",
                    },
                ))

    def _scan_npm_lockfile(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        for name, version in _iter_npm_packages(doc):
            key = ("npm", name.lower())
            for adv in index.get(key, []):
                emit(Finding(
                    probe_id=self.id,
                    algorithm=adv.get("id", "N/A"),
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=(f"{adv.get('id', '?')} affects {name}@{version} "
                           f"in {path.name}"),
                    evidence={
                        "advisory_id": adv.get("id", ""),
                        "package": name, "version": version,
                        "summary": (adv.get("summary") or "")[:200],
                        "path": str(path),
                        "ecosystem": "npm",
                    },
                ))

    def _scan_cargo_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _CARGO_PACKAGE_RE.finditer(text):
            name, version = m.group(1), m.group(2)
            key = ("crates.io", name.lower())
            for adv in index.get(key, []):
                emit(Finding(
                    probe_id=self.id,
                    algorithm=adv.get("id", "N/A"),
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=(f"{adv.get('id', '?')} affects {name} {version} "
                           f"in {path.name}"),
                    evidence={
                        "advisory_id": adv.get("id", ""),
                        "package": name, "version": version,
                        "summary": (adv.get("summary") or "")[:200],
                        "path": str(path),
                        "ecosystem": "crates.io",
                    },
                ))

    def _scan_go_sum(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        # go.sum lists each module twice (one for the module, one for its
        # go.mod). De-duplicate by (module, version).
        seen: set = set()
        for m in _GO_SUM_LINE_RE.finditer(text):
            module, version = m.group(1), m.group(2)
            if (module, version) in seen:
                continue
            seen.add((module, version))
            key = ("go", module.lower())
            for adv in index.get(key, []):
                emit(Finding(
                    probe_id=self.id,
                    algorithm=adv.get("id", "N/A"),
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=(f"{adv.get('id', '?')} affects {module} {version} "
                           f"in {path.name}"),
                    evidence={
                        "advisory_id": adv.get("id", ""),
                        "package": module, "version": version,
                        "summary": (adv.get("summary") or "")[:200],
                        "path": str(path),
                        "ecosystem": "Go",
                    },
                ))

    def _scan_pipfile_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """Pipfile.lock — JSON, exact pins under default/ + develop/."""
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        for section in ("default", "develop"):
            for name, info in (doc.get(section) or {}).items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version") or ""
                # Pipenv writes pinned versions as "==1.2.3"; tolerate
                # bare versions just in case.
                if version.startswith("=="):
                    version = version[2:]
                if not version:
                    continue
                self._emit_pypi_match(name, version, path, index, emit)

    def _scan_poetry_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """poetry.lock — TOML, [[package]] / name / version blocks."""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _POETRY_PACKAGE_RE.finditer(text):
            self._emit_pypi_match(m.group(1), m.group(2), path, index, emit)

    def _emit_pypi_match(
        self, name: str, version: str, path: Path,
        index: dict, emit: Emitter,
    ) -> None:
        """Shared PyPI-match-and-emit helper for the lockfile parsers."""
        key = ("pypi", name.lower())
        for adv in index.get(key, []):
            emit(Finding(
                probe_id=self.id,
                algorithm=adv.get("id", "N/A"),
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=(f"{adv.get('id', '?')} affects {name}=={version} "
                       f"in {path.name}"),
                evidence={
                    "advisory_id": adv.get("id", ""),
                    "package": name, "version": version,
                    "summary": (adv.get("summary") or "")[:200],
                    "path": str(path),
                    "ecosystem": "PyPI",
                },
            ))

    def _scan_composer_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """composer.lock — JSON; iterate packages + packages-dev."""
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        for section in ("packages", "packages-dev"):
            for pkg in (doc.get(section) or []):
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name") or ""
                version = pkg.get("version") or ""
                # Composer pins like "v6.4.0" — strip the optional "v".
                if version.startswith("v"):
                    version = version[1:]
                if not name or not version:
                    continue
                self._emit_simple_match(
                    "packagist", name, version, path, index, emit,
                    ecosystem_label="Packagist",
                )

    def _scan_nuget_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """packages.lock.json — NuGet; iterate every framework's deps."""
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        seen: set = set()
        for _framework, deps in (doc.get("dependencies") or {}).items():
            if not isinstance(deps, dict):
                continue
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("resolved") or ""
                if not name or not version:
                    continue
                if (name.lower(), version) in seen:
                    continue
                seen.add((name.lower(), version))
                self._emit_simple_match(
                    "nuget", name, version, path, index, emit,
                    ecosystem_label="NuGet",
                )

    def _scan_mix_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """mix.lock — Elixir/Hex; '"name": {:hex, :name, "version",' lines."""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _MIX_LOCK_RE.finditer(text):
            name, version = m.group(1), m.group(2)
            self._emit_simple_match(
                "hex", name, version, path, index, emit,
                ecosystem_label="Hex",
            )

    def _scan_pub_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """pubspec.lock — Dart/Flutter; YAML 'packages.<name>.version'."""
        try:
            doc = yaml.safe_load(path.read_text(errors="replace"))
        except (OSError, yaml.YAMLError):
            return
        if not isinstance(doc, dict):
            return
        for name, info in (doc.get("packages") or {}).items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if not isinstance(version, str) or not version:
                continue
            self._emit_simple_match(
                "pub", name, version, path, index, emit,
                ecosystem_label="Pub",
            )

    def _scan_gradle_lockfile(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """gradle.lockfile — JVM; '<group>:<artifact>:<version>=<configs>'."""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _GRADLE_LOCK_LINE_RE.finditer(text):
            group, artifact, version = m.group(1), m.group(2), m.group(3)
            full_name = f"{group}:{artifact}"
            self._emit_simple_match(
                "maven", full_name, version, path, index, emit,
                ecosystem_label="Maven",
            )

    def _scan_gemfile_lock(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        """Gemfile.lock — '    name (version)' lines under GEM/specs:."""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        # Restrict to the GEM section to skip GIT/PATH/DEPENDENCIES blocks.
        gem_block = _extract_gemfile_gem_section(text)
        if gem_block is None:
            return
        seen: set = set()
        for m in _GEMFILE_SPEC_RE.finditer(gem_block):
            name, version = m.group(1), m.group(2)
            if (name, version) in seen:
                continue
            seen.add((name, version))
            self._emit_simple_match(
                "rubygems", name, version, path, index, emit,
                ecosystem_label="RubyGems",
            )

    def _emit_simple_match(
        self, ecosystem_key: str, name: str, version: str,
        path: Path, index: dict, emit: Emitter,
        *, ecosystem_label: str,
    ) -> None:
        """Generic match-and-emit, parameterised on the OSV ecosystem key."""
        key = (ecosystem_key, name.lower())
        for adv in index.get(key, []):
            emit(Finding(
                probe_id=self.id,
                algorithm=adv.get("id", "N/A"),
                classification=Classification.TINGGI,
                severity=Severity.HIGH,
                title=(f"{adv.get('id', '?')} affects {name} {version} "
                       f"in {path.name}"),
                evidence={
                    "advisory_id": adv.get("id", ""),
                    "package": name, "version": version,
                    "summary": (adv.get("summary") or "")[:200],
                    "path": str(path),
                    "ecosystem": ecosystem_label,
                },
            ))


def _extract_gemfile_gem_section(text: str) -> str | None:
    """Return only the body of the 'GEM ... specs:' block, or None.

    Gemfile.lock has multiple top-level sections (GEM, GIT, PATH, PLATFORMS,
    DEPENDENCIES, RUBY VERSION, BUNDLED WITH). We only want gem versions
    from the GEM section's specs: list — DEPENDENCIES lists requirement
    ranges that we'd misread as exact versions.
    """
    lines = text.splitlines()
    in_gem = False
    in_specs = False
    out: list[str] = []
    for line in lines:
        # Top-level section headers are unindented.
        if line and not line[0].isspace():
            if line.strip() == "GEM":
                in_gem = True
                in_specs = False
                continue
            in_gem = False
            in_specs = False
            continue
        if not in_gem:
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            out.append(line)
    return "\n".join(out) if out else None


def _iter_npm_packages(doc: dict):
    """Yield (name, version) for every package in a package-lock.json doc.

    Handles both npm v7+ (``packages`` dict keyed by node_modules path)
    and npm v6 (``dependencies`` dict keyed by name, recursive).
    """
    packages = doc.get("packages")
    if isinstance(packages, dict):
        # npm v7+
        for path_key, pkg in packages.items():
            if not path_key:  # skip the "" root entry
                continue
            if not isinstance(pkg, dict):
                continue
            version = pkg.get("version")
            if not version:
                continue
            # path_key is like "node_modules/lodash" or
            # "node_modules/@types/node". Strip the leading
            # "node_modules/" segments and keep what's left, which is
            # the package name (preserving any "@scope/" prefix).
            parts = path_key.split("node_modules/")
            name = parts[-1]
            if name:
                yield name, version
        return
    # npm v6 — recursive "dependencies" tree.
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        yield from _walk_npm_v6(deps)


def _walk_npm_v6(deps: dict):
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if version:
            yield name, version
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            yield from _walk_npm_v6(nested)


_EXACT_PIN_RE = re.compile(r"^==\s*[A-Za-z0-9._+!*-]+$")


def _spec_is_exact_pin(spec_str: str) -> bool:
    """True if the constraint is a single ``==X.Y.Z`` clause."""
    return bool(_EXACT_PIN_RE.match(spec_str.strip()))


def _osv_candidate_versions(advisory: dict) -> list[str]:
    """Extract candidate vulnerable version strings from an OSV record.

    Walks both ``affected[].versions`` (explicit list) and
    ``affected[].ranges[].events[]`` (introduced/fixed boundaries).
    Returns string forms — the caller filters via packaging.Version.
    """
    out: list[str] = []
    for aff in advisory.get("affected") or []:
        for v in aff.get("versions") or []:
            if isinstance(v, str):
                out.append(v)
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                introduced = ev.get("introduced")
                if isinstance(introduced, str) and introduced not in {"", "0"}:
                    out.append(introduced)
                # We don't add `fixed` itself — that version is *not*
                # vulnerable per OSV semantics.
    return out


def _advisory_matches_specifier(
    spec_str: str, advisory: dict,
) -> tuple[bool, str | None]:
    """Return (match?, sample) where sample is a vulnerable version that
    satisfies ``spec_str``. Empty/invalid specifier means "no version
    constraint" → any vulnerable version satisfies → match if the
    advisory has any candidate version at all.
    """
    candidates = _osv_candidate_versions(advisory)
    try:
        spec = SpecifierSet(spec_str) if spec_str else SpecifierSet("")
    except InvalidSpecifier:
        return (False, None)
    for v in candidates:
        try:
            ver = Version(v)
        except InvalidVersion:
            continue
        if spec.contains(str(ver), prereleases=True):
            return (True, str(ver))
    # No candidate-version overlap. Conservative fallback: if the spec
    # is empty (no constraint) and there are *any* candidate versions,
    # call it a match — an unconstrained "name" line allows everything.
    if not spec_str and candidates:
        return (True, candidates[0])
    return (False, None)


def _load_snapshot_index(path: Path) -> dict:
    """Return ``{(ecosystem_lower, name_lower): [osv_record, ...]}``.

    Accepts JSONL (one record per line) or a JSON array. Returns an empty
    dict on parse error so the caller can degrade gracefully.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return {}
    records = _parse_records(text)
    index: dict = {}
    for rec in records:
        # An OSV record can list the same package multiple times under
        # different `affected[]` entries (typically different version
        # ranges). Insert each (ecosystem, name) key only once per
        # record so the matcher doesn't emit duplicate findings.
        seen_keys: set = set()
        for aff in rec.get("affected") or []:
            pkg = aff.get("package") or {}
            ecosystem = (pkg.get("ecosystem") or "").lower()
            name = (pkg.get("name") or "").lower()
            if not ecosystem or not name:
                continue
            key = (ecosystem, name)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            index.setdefault(key, []).append(rec)
    return index


def _parse_records(text: str) -> list:
    text = text.lstrip()
    if not text:
        return []
    if text.startswith("["):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []
        return doc if isinstance(doc, list) else []
    # JSONL
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
