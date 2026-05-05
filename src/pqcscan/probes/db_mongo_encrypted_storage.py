"""db.mongo.encrypted_storage — MongoDB at-rest encryption (WiredTiger).

Looks for security.encryption.* entries in mongod.conf. AES-CBC modes
are flagged TINGGI (not authenticated); GCM is informational. KMIP /
keyfile presence is informational.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_KEYFILE_RE = re.compile(
    r"^\s*encryptionKeyFile\s*:\s*['\"]?([^'\"\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_CIPHER_RE = re.compile(
    r"^\s*encryptionCipherMode\s*:\s*['\"]?([^'\"\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_KMIP_RE = re.compile(
    r"^\s*serverName\s*:\s*['\"]?([^'\"\n#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"mongod.conf", "mongod.yml", "mongod.yaml"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class DbMongoEncryptedStorage(Probe):
    id = "db.mongo.encrypted_storage"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:db-tde", "bukukerja:db-tde",
                      "mykripto:db-tde")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/etc"), Path("/etc/mongod"),
                               Path("/etc/mongodb")]

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
                if path.name not in _NAMES:
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return

        for m in _KEYFILE_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id, algorithm="WiredTiger-keyfile",
                classification=Classification.INFO, severity=Severity.INFO,
                title=(f"WiredTiger encryptionKeyFile configured "
                       f"in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": "encryptionKeyFile"},
            ))

        for m in _CIPHER_RE.finditer(text):
            value = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            up = value.upper()
            if "CBC" in up:
                cls = Classification.TINGGI
                sev = Severity.HIGH
            else:
                cls = Classification.INFO
                sev = Severity.INFO
            emit(Finding(
                probe_id=self.id, algorithm=value,
                classification=cls, severity=sev,
                title=(f"WiredTiger cipher mode {value} "
                       f"in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": "encryptionCipherMode",
                          "value": value},
            ))

        for m in _KMIP_RE.finditer(text):
            value = m.group(1).strip()
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id, algorithm="KMIP",
                classification=Classification.INFO, severity=Severity.INFO,
                title=(f"KMIP serverName={value} configured "
                       f"in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": "serverName", "kmip_host": value},
            ))
