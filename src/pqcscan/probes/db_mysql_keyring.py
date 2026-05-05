"""db.mysql.keyring — at-rest TDE keyring config in MySQL my.cnf.

MySQL InnoDB tablespace encryption requires a keyring plugin. This probe
detects which keyring plugin is loaded and where the master key lives.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_PLUGIN_LOAD_RE = re.compile(
    r"^\s*(early-plugin-load|plugin-load-add|plugin-load)\s*=\s*([^\s#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_KEYRING_DATA_RE = re.compile(
    r"^\s*(keyring_file_data|keyring_aws_cmk_id|"
    r"keyring_okv_conf_dir|keyring_oci_master_key)\s*=\s*([^\s#]+)",
    re.IGNORECASE | re.MULTILINE,
)
_INNODB_ENCRYPT_RE = re.compile(
    r"^\s*(innodb_encrypt_tables|innodb_encrypt_log|"
    r"innodb_redo_log_encrypt|innodb_undo_log_encrypt)"
    r"\s*=\s*(ON|OFF|FORCE)\b",
    re.IGNORECASE | re.MULTILINE,
)
_NAMES = {"my.cnf", "mysql.cnf", "mariadb.cnf", "my-default.cnf"}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class DbMysqlKeyring(Probe):
    id = "db.mysql.keyring"
    family = ProbeFamily.STORAGE
    framework_tags = ("nist-ir-8547:db-tde", "bukukerja:db-tde",
                      "mykripto:db-tde")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/mysql"), Path("/etc"),
            Path("/etc/my.cnf.d"), Path("/etc/mysql/conf.d"),
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
                if name not in _NAMES and not name.endswith(".cnf"):
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return

        for m in _PLUGIN_LOAD_RE.finditer(text):
            value = m.group(2).strip()
            if "keyring" not in value.lower():
                continue
            line_no = text[: m.start()].count("\n") + 1
            cls = (Classification.SEDERHANA if "keyring_file" in value.lower()
                   else Classification.INFO)
            emit(Finding(
                probe_id=self.id, algorithm=f"mysql-keyring/{value}",
                classification=cls,
                severity=Severity.MED if cls == Classification.SEDERHANA
                else Severity.INFO,
                title=f"MySQL keyring plugin {value} in {path.name}:{line_no}",
                evidence={"path": str(path), "line": line_no,
                          "directive": m.group(1), "plugin": value},
            ))

        for m in _KEYRING_DATA_RE.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id, algorithm=f"mysql-{m.group(1)}",
                classification=Classification.INFO, severity=Severity.INFO,
                title=f"{m.group(1)} configured in {path.name}:{line_no}",
                evidence={"path": str(path), "line": line_no,
                          "directive": m.group(1)},
            ))

        for m in _INNODB_ENCRYPT_RE.finditer(text):
            value = m.group(2).upper()
            if value == "OFF":
                continue
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm=f"InnoDB-TDE/{m.group(1)}={value}",
                classification=Classification.INFO, severity=Severity.INFO,
                title=(f"InnoDB at-rest encryption enabled "
                       f"({m.group(1)}={value}) in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "directive": m.group(1), "value": value},
            ))
