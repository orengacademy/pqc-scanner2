"""db.pg.pgcrypto — flag classical-only pgcrypto usage in postgresql.conf.

PostgreSQL's pgcrypto extension exposes RSA / AES / SHA-2 primitives.
Findings are informational unless the config explicitly references a
broken primitive (e.g. MD5, SHA1, RC2). Absence of pgcrypto + lack of
TDE entries are not flagged here — that's a deployment policy choice,
not a config defect.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_SHARED_PRELOAD_RE = re.compile(
    r"^\s*shared_preload_libraries\s*=\s*['\"]?([^'\"\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_BAD_ALGS_RE = re.compile(
    r"\b(md5|sha1|rc2|rc4|des|3des|tdes|blowfish)\b",
    re.IGNORECASE,
)
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class DbPgPgcrypto(Probe):
    id = "db.pg.pgcrypto"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:db-tde", "bukukerja:db-tde",
                      "mykripto:db-tde")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/postgresql"), Path("/var/lib/pgsql"),
            Path("/var/lib/postgresql"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            walker = [root] if root.is_file() else list(root.rglob("*"))
            for path in walker:
                if not path.is_file():
                    continue
                if any(part in _EXCLUDE_DIRS for part in path.parts):
                    continue
                name = path.name
                if name not in {"postgresql.conf", "postgresql.auto.conf"}:
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _SHARED_PRELOAD_RE.finditer(text):
            value = m.group(1).strip()
            if "pgcrypto" not in value.lower():
                continue
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id, algorithm="pgcrypto",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"pgcrypto preloaded in {path.name}:{line_no}",
                evidence={"path": str(path), "line": line_no,
                          "directive": "shared_preload_libraries"},
            ))
        for m in _BAD_ALGS_RE.finditer(text):
            alg = m.group(1).upper()
            cls = classify(normalise(alg))
            if cls not in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                continue
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id, algorithm=alg,
                classification=cls, severity=sev_for(cls),
                title=f"deprecated {alg} reference in {path.name}:{line_no}",
                evidence={"path": str(path), "line": line_no, "alg": alg},
            ))
