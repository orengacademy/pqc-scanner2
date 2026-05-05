"""app.oauth.jwks — parse OAuth/OIDC JWKS files for algorithm + key strength."""
from __future__ import annotations

import json
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._severity import sev_for

_GLOBS = ("**/jwks.json", "**/.well-known/jwks.json", "**/*jwks*.json")


class AppOauthJwks(Probe):
    id = "app.oauth.jwks"
    family = ProbeFamily.APP
    framework_tags = ("nist-ir-8547:oauth", "bukukerja:oauth", "mykripto:oauth")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for pattern in _GLOBS:
                for path in root.glob(pattern):
                    self._scan(path, emit)

    def _scan(self, path: Path, emit: Emitter) -> None:
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        for key in doc.get("keys", []) or []:
            kty = key.get("kty", "")
            alg = key.get("alg", "")
            kid = key.get("kid", "")
            n = key.get("n", "")  # RSA modulus (base64url)
            crv = key.get("crv", "")
            # RSA key size = ~length of base64-decoded modulus * 8.
            # Approximate: each 4 base64 chars -> 3 bytes. So bits ≈ len(n)*6.
            if kty == "RSA" and n:
                approx_bits = len(n) * 6
                cls = (Classification.SANGAT_TINGGI if approx_bits < 3072
                       else Classification.TINGGI)
                emit(Finding(
                    probe_id=self.id,
                    algorithm=f"RSA-{approx_bits}",
                    classification=cls, severity=sev_for(cls),
                    title=f"JWKS RSA key kid={kid} ~{approx_bits} bits in {path.name}",
                    evidence={"path": str(path), "kid": kid, "alg": alg,
                              "approx_bits": approx_bits},
                ))
            elif kty == "EC":
                emit(Finding(
                    probe_id=self.id,
                    algorithm=f"ECDSA-{crv or 'unknown'}",
                    classification=Classification.TINGGI,
                    severity=Severity.HIGH,
                    title=f"JWKS EC key kid={kid} curve={crv} in {path.name}",
                    evidence={"path": str(path), "kid": kid, "alg": alg, "crv": crv},
                ))
            elif kty == "OKP" and crv in ("Ed25519", "Ed448"):
                emit(Finding(
                    probe_id=self.id,
                    algorithm=crv,
                    classification=Classification.TINGGI,  # Shor-vulnerable
                    severity=Severity.HIGH,
                    title=f"JWKS {crv} key kid={kid} in {path.name}",
                    evidence={"path": str(path), "kid": kid, "alg": alg, "crv": crv},
                ))
