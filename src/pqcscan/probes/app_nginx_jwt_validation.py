"""app.nginx.jwt_validation — flag nginx auth_jwt directives + algorithm choice."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_AUTH_JWT_RE = re.compile(r"^\s*(auth_jwt[a-z_]*)\s+(.+);", re.IGNORECASE | re.MULTILINE)


class AppNginxJwtValidation(Probe):
    id = "app.nginx.jwt_validation"
    family = ProbeFamily.APP
    framework_tags = ("nist-ir-8547:jwt", "bukukerja:jwt", "mykripto:jwt")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/nginx"),
            Path("/srv"), Path("/opt"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*.conf"):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                for m in _AUTH_JWT_RE.finditer(text):
                    directive, value = m.group(1), m.group(2).strip()
                    line_no = text[: m.start()].count("\n") + 1
                    cls = (Classification.SANGAT_TINGGI
                           if directive.lower() == "auth_jwt_alg" and "HS" in value.upper()
                           and "256" in value
                           else Classification.TINGGI)
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=f"nginx-{directive}",
                        classification=cls,
                        severity=Severity.HIGH,
                        title=f"nginx {directive} = {value} in {path.name}:{line_no}",
                        evidence={"path": str(path), "line": line_no,
                                  "directive": directive, "value": value},
                    ))
