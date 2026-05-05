"""app.jwt.env_alg — find JWT alg / signing-key declarations in env/yaml/json.

Targets:
  - .env / .env.* files                  (KEY=VALUE)
  - systemd unit Environment= entries    (KEY=VALUE)
  - kubernetes manifests / docker-compose env: blocks (yaml/json)
  - app config files application.{yml,yaml,properties}

Detects:
  - JWT_ALG, JWT_ALGORITHM, jwt.alg with HS256/HS384/HS512/RS256/RS384/RS512
    /ES256/ES384/ES512/PS256/PS384/PS512/none/None
  - JWT_SECRET / jwt.secret with very short values (<32 chars) — Tinggi
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_ALG_RE = re.compile(
    r"""(?ix)
        \b(jwt[._-]?alg(?:orithm)?|JWS_?ALG)\b
        \s*[:=]\s*
        ['"]?(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|
              PS256|PS384|PS512|EdDSA|none|None)['"]?
    """,
    re.VERBOSE,
)
_SECRET_RE = re.compile(
    r"""(?ix)
        \b(jwt[._-]?secret|jwt[._-]?key|JWS_?SECRET)\b
        \s*[:=]\s*
        ['"]?([^\s'"#;]+)['"]?
    """,
    re.VERBOSE,
)

_TARGET_NAMES = {
    "application.properties", "application.yml", "application.yaml",
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.override.yml", "docker-compose.override.yaml",
}
_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", "vendor"}


def _is_target(path: Path) -> bool:
    if not path.is_file():
        return False
    if any(part in _EXCLUDE_DIRS for part in path.parts):
        return False
    name = path.name
    if name in _TARGET_NAMES:
        return True
    # .env / .env.* — Path.glob in <3.13 does not match dotfiles by default.
    if name == ".env" or name.startswith(".env."):
        return True
    if name.endswith(".service"):  # systemd unit files
        return True
    if (name.startswith("application-")
            and (name.endswith(".properties") or name.endswith(".yml")
                 or name.endswith(".yaml"))):
        return True
    return False


_ALG_CLASS = {
    "HS256": Classification.TINGGI,        # 256-bit MAC, but secret strength varies
    "HS384": Classification.SEDERHANA,
    "HS512": Classification.RENDAH,
    "RS256": Classification.TINGGI,        # RSA — Shor-vulnerable
    "RS384": Classification.TINGGI,
    "RS512": Classification.TINGGI,
    "ES256": Classification.TINGGI,        # ECDSA-P256
    "ES384": Classification.TINGGI,
    "ES512": Classification.TINGGI,
    "PS256": Classification.TINGGI,
    "PS384": Classification.TINGGI,
    "PS512": Classification.TINGGI,
    "EdDSA": Classification.TINGGI,
    "none":  Classification.SANGAT_TINGGI,
    "None":  Classification.SANGAT_TINGGI,
}


class AppJwtEnvAlg(Probe):
    id = "app.jwt.env_alg"
    family = ProbeFamily.APP
    framework_tags = ("nist-ir-8547:jwt", "bukukerja:jwt", "mykripto:jwt")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/srv"), Path("/opt"), Path("/var/www"),
            Path("/etc/systemd"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            walker = [root] if root.is_file() else list(root.rglob("*"))
            for path in walker:
                if _is_target(path):
                    self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for m in _ALG_RE.finditer(text):
            alg = m.group(2)
            cls = _ALG_CLASS.get(alg, Classification.INFO)
            line_no = text[: m.start()].count("\n") + 1
            emit(Finding(
                probe_id=self.id,
                algorithm=f"JWT-{alg}",
                classification=cls, severity=sev_for(cls),
                title=f"JWT algorithm = {alg} in {path.name}:{line_no}",
                evidence={"path": str(path), "line": line_no,
                          "directive": m.group(1), "alg": alg},
            ))
        for m in _SECRET_RE.finditer(text):
            secret = m.group(2)
            if len(secret) < 32:
                line_no = text[: m.start()].count("\n") + 1
                emit(Finding(
                    probe_id=self.id,
                    algorithm="JWT-SECRET-WEAK",
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"JWT secret <32 chars in {path.name}:{line_no}",
                    evidence={"path": str(path), "line": line_no,
                              "directive": m.group(1),
                              "secret_length": len(secret),
                              "secret_redacted": True},
                ))
