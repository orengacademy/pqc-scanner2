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

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_DEFAULT_SNAPSHOT = Path("/var/lib/pqcscan/osv-snapshot.jsonl")
_ENV_SNAPSHOT = "PQCSCAN_OSV_SNAPSHOT"

# Capture "name==version", "name>=version", "name~=version" etc.
_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|>=|<=|~=|!=|>|<)\s*"
    r"([A-Za-z0-9._-]+)",
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

    def _scan_requirements(
        self, path: Path, index: dict, emit: Emitter,
    ) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _REQ_LINE_RE.finditer(text):
            name, op, version = m.group(1), m.group(2), m.group(3)
            # Conservative: only match exact-pin "==". Range comparisons
            # would need a full PEP 440 evaluator — out of scope for v1.
            if op != "==":
                continue
            key = ("pypi", name.lower())
            for adv in index.get(key, []):
                line_no = text[: m.start()].count("\n") + 1
                emit(Finding(
                    probe_id=self.id,
                    algorithm=adv.get("id", "N/A"),
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=(f"{adv.get('id', '?')} affects {name}=={version} "
                           f"in {path.name}:{line_no}"),
                    evidence={
                        "advisory_id": adv.get("id", ""),
                        "package": name, "version": version,
                        "summary": (adv.get("summary") or "")[:200],
                        "path": str(path), "line": line_no,
                        "ecosystem": "PyPI",
                    },
                ))


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
        for aff in rec.get("affected") or []:
            pkg = aff.get("package") or {}
            ecosystem = (pkg.get("ecosystem") or "").lower()
            name = (pkg.get("name") or "").lower()
            if not ecosystem or not name:
                continue
            index.setdefault((ecosystem, name), []).append(rec)
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
