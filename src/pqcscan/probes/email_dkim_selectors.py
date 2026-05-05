"""email.dkim.selectors — DKIM key files and selectors. RSA <2048 -> Sangat Tinggi."""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_DKIM_TXT_RE = re.compile(
    r"v=DKIM1\s*;.*?p=([A-Za-z0-9+/=]+)", re.DOTALL,
)


class EmailDkimSelectors(Probe):
    id = "email.dkim.selectors"
    family = ProbeFamily.DNS_EMAIL
    framework_tags = ("nist-ir-8547:dkim", "bukukerja:dkim", "mykripto:dkim")

    def __init__(self, roots: list[Path] | None = None):
        self.roots = roots or [
            Path("/etc/opendkim"),
            Path("/etc/dkim"),
            Path("/var/db/dkim"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                # Private DKIM keys: *.private files
                if path.suffix == ".private":
                    self._check_private_key(path, emit)
                # DKIM published TXT records (often kept as *.txt)
                if path.suffix == ".txt":
                    self._check_txt(path, emit)

    def _check_private_key(self, path: Path, emit: Emitter) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            data = path.read_bytes()
            key = load_pem_private_key(data, password=None)
            if isinstance(key, rsa.RSAPrivateKey):
                bits = key.key_size
                cls = (Classification.SANGAT_TINGGI if bits < 2048
                       else Classification.TINGGI)
                emit(Finding(
                    probe_id=self.id,
                    algorithm=f"RSA-{bits}",
                    classification=cls,
                    severity=Severity.CRIT if bits < 2048 else Severity.HIGH,
                    title=f"DKIM private key {path.name} = RSA-{bits}",
                    evidence={"path": str(path), "bits": bits},
                ))
        except Exception:
            return

    def _check_txt(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        m = _DKIM_TXT_RE.search(text)
        if not m:
            return
        # Approximate RSA key size from base64 length.
        b64_len = len(m.group(1))
        approx_bits = b64_len * 6
        cls = (Classification.SANGAT_TINGGI if approx_bits < 2048
               else Classification.TINGGI)
        emit(Finding(
            probe_id=self.id,
            algorithm=f"RSA-{approx_bits}",
            classification=cls,
            severity=Severity.CRIT if approx_bits < 2048 else Severity.HIGH,
            title=f"DKIM published key in {path.name} ~{approx_bits} bits",
            evidence={"path": str(path), "approx_bits": approx_bits},
        ))
