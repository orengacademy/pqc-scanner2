"""app.dotenv.secrets — flag obvious crypto-related secrets in .env files."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_KEY_RE = re.compile(
    r"""(?ix)
        \b(SECRET_KEY|API_KEY|API_SECRET|AWS_SECRET_ACCESS_KEY|
           DJANGO_SECRET_KEY|RAILS_MASTER_KEY|FLASK_SECRET_KEY|
           ENCRYPTION_KEY|ENCRYPTION_PASSPHRASE|JWT_SECRET|HMAC_KEY)\b
        \s*=\s*
        ['"]?([^\s'"#]+)['"]?
    """,
    re.VERBOSE,
)
_GLOBS = ("**/.env", "**/.env.*", "**/*.env")
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


class AppDotenvSecrets(Probe):
    id = "app.dotenv.secrets"
    family = ProbeFamily.APP
    framework_tags = ("bukukerja:secrets", "mykripto:secrets")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

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
                name = path.name
                if not (name == ".env" or name.startswith(".env.")
                        or name.endswith(".env")):
                    continue
                if any(part in _EXCLUDE_DIRS for part in path.parts):
                    continue
                self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _KEY_RE.finditer(text):
            key_name = m.group(1)
            value = m.group(2)
            line_no = text[: m.start()].count("\n") + 1
            short = len(value) < 32
            emit(Finding(
                probe_id=self.id,
                algorithm=f"DOTENV-{key_name}",
                classification=Classification.SANGAT_TINGGI if short
                else Classification.TINGGI,
                severity=Severity.CRIT if short else Severity.HIGH,
                title=(f"crypto secret {key_name} "
                       f"({'short' if short else 'present'}) in {path.name}:{line_no}"),
                evidence={"path": str(path), "line": line_no,
                          "key": key_name, "length": len(value),
                          "secret_redacted": True},
            ))
