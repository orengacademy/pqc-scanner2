"""web.webauthn.config — WebAuthn relying-party configuration."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext


_WEBAUTHN_RE = re.compile(
    r"""(?ix)
        \b(rp_?id|relying_?party_?id|webauthn_?rp|fido2_?rp|webauthn[._-]?origins?)\b
        \s*[:=]\s*['"]?([^\s'"#;,\]]+)
    """,
    re.VERBOSE,
)
_ALG_RE = re.compile(
    r"""(?ix)
        \b(pubKeyCredParams|webauthn_?algorithms?|fido2_?algs?)\b
        \s*[:=]\s*['"]?([\-A-Z0-9,\s]+)
    """,
    re.VERBOSE,
)


class WebWebauthnConfig(Probe):
    id = "web.webauthn.config"
    family = ProbeFamily.DNS_EMAIL
    framework_tags = ("bukukerja:webauthn", "mykripto:webauthn")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix not in {".yml", ".yaml", ".json", ".toml",
                                        ".conf", ".env", ".properties"}:
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                # Detect relying-party config presence (INFO).
                if _WEBAUTHN_RE.search(text):
                    emit(Finding(
                        probe_id=self.id,
                        algorithm="WEBAUTHN-RP",
                        classification=Classification.INFO,
                        severity=Severity.INFO,
                        title=f"WebAuthn relying-party config in {path.name}",
                        evidence={"path": str(path)},
                    ))
                # Detect explicit alg lists. -7 = ES256, -257 = RS256, -8 = EdDSA.
                m = _ALG_RE.search(text)
                if m:
                    alg_str = m.group(2)
                    flagged = []
                    if "-257" in alg_str or "RS256" in alg_str.upper():
                        flagged.append("RS256 (RSA — Shor-vulnerable)")
                    if "-7" in alg_str or "ES256" in alg_str.upper():
                        flagged.append("ES256 (ECDSA — Shor-vulnerable)")
                    if flagged:
                        emit(Finding(
                            probe_id=self.id,
                            algorithm="WEBAUTHN-ALGS",
                            classification=Classification.TINGGI,
                            severity=Severity.MED,
                            title=f"WebAuthn algorithms in {path.name}: " + ", ".join(flagged),
                            evidence={"path": str(path), "raw": alg_str.strip()},
                        ))
