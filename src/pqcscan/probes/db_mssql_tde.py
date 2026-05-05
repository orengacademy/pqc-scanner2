"""db.mssql.tde — Microsoft SQL Server transparent-data-encryption config.

Linux SQL Server uses /var/opt/mssql/mssql.conf (mssql-conf format, INI
with [section] / key = value). This probe surfaces TLS-protocol limits
and EKM/HSM hints. We don't try to crack the master-key DPAPI store.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.alg import classify, normalise
from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_TLS_PROTO_RE = re.compile(
    r"^\s*(tlsprotocols)\s*=\s*([^#\n]+)",
    re.IGNORECASE | re.MULTILINE,
)
_TLS_CIPHER_RE = re.compile(
    r"^\s*(tlsciphers)\s*=\s*([^#\n]+)",
    re.IGNORECASE | re.MULTILINE,
)
_FORCE_ENCRYPT_RE = re.compile(
    r"^\s*(forceencryption)\s*=\s*([01])",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"mssql.conf", "mssql-conf"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class DbMssqlTde(Probe):
    id = "db.mssql.tde"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:db-tde", "bukukerja:db-tde",
                      "mykripto:db-tde")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/var/opt/mssql"), Path("/etc/mssql")]

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

        for m in _TLS_PROTO_RE.finditer(text):
            value = m.group(2).strip()
            line_no = text[: m.start()].count("\n") + 1
            tokens = [t.strip() for t in re.split(r"[,;\s]+", value) if t.strip()]
            for tok in tokens:
                if tok in {"1.0", "1.1"}:
                    emit(Finding(
                        probe_id=self.id, algorithm=f"TLSv{tok}",
                        classification=Classification.SANGAT_TINGGI,
                        severity=Severity.CRIT,
                        title=(f"MSSQL allows TLSv{tok} via tlsprotocols "
                               f"in {path.name}:{line_no}"),
                        evidence={"path": str(path), "line": line_no,
                                  "directive": "tlsprotocols", "value": tok},
                    ))

        for m in _TLS_CIPHER_RE.finditer(text):
            value = m.group(2).strip()
            line_no = text[: m.start()].count("\n") + 1
            for tok in re.split(r"[:,]", value):
                tok = tok.strip()
                if not tok:
                    continue
                cls = classify(normalise(tok))
                if cls in {Classification.SANGAT_TINGGI, Classification.TINGGI}:
                    emit(Finding(
                        probe_id=self.id, algorithm=tok,
                        classification=cls, severity=sev_for(cls),
                        title=(f"MSSQL tlsciphers includes weak {tok} "
                               f"in {path.name}:{line_no}"),
                        evidence={"path": str(path), "line": line_no,
                                  "directive": "tlsciphers", "cipher": tok},
                    ))

        for m in _FORCE_ENCRYPT_RE.finditer(text):
            value = m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.INFO if value == "1"
                   else Classification.TINGGI)
            emit(Finding(
                probe_id=self.id,
                algorithm=f"forceencryption={value}",
                classification=cls,
                severity=Severity.INFO if cls == Classification.INFO
                else Severity.HIGH,
                title=(f"MSSQL forceencryption={value} "
                       f"in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": "forceencryption", "value": value},
            ))
