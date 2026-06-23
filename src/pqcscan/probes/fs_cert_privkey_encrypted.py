"""fs.cert.privkey_encrypted — encrypted private keys at rest (+ legacy KDF).

The sibling fs.cert.privkey probe reads *unencrypted* keys; password-protected
keys can't be opened, but they still matter: the wrapped key is classical
RSA/EC (quantum-vulnerable), and the at-rest protection itself can be weak.
This probe inventories encrypted private keys via their PEM headers (no
password needed) and flags legacy PEM encryption (the MD5-based KDF, and weak
DES/3DES/RC2 ciphers) more highly than modern PKCS#8 PBES2.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_EXTS = (".pem", ".key")
_PKCS8_ENC = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
_LEGACY_MARK = "Proc-Type: 4,ENCRYPTED"
_DEK_RE = re.compile(r"^DEK-Info:\s*([A-Za-z0-9-]+)", re.MULTILINE)
_WEAK_CIPHERS = ("DES-CBC", "DES-EDE3-CBC", "DES-EDE-CBC", "RC2")


def _sev(c: Classification) -> Severity:
    return {
        Classification.SANGAT_TINGGI: Severity.CRIT,
        Classification.TINGGI: Severity.HIGH,
        Classification.SEDERHANA: Severity.MED,
        Classification.RENDAH: Severity.LOW,
        Classification.PQC_READY: Severity.INFO,
        Classification.INFO: Severity.INFO,
        Classification.ERROR: Severity.INFO,
    }[c]


class FsCertPrivkeyEncrypted(Probe):
    """Inventory encrypted private keys and flag weak at-rest protection."""

    id = "fs.cert.privkey_encrypted"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:cert", "bukukerja:cert", "mykripto:cert")

    def __init__(self, roots: list[Path] | None = None) -> None:
        self.roots = roots or [
            Path("/etc/ssl"), Path("/etc/pki"), Path("/etc/ssl/private"),
        ]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        seen: set[Path] = set()
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not (path.is_file() and path.suffix.lower() in _EXTS):
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                self._scan_one(path, emit)

    def _scan_one(self, path: Path, emit: Emitter) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return

        if _PKCS8_ENC in text:
            emit(Finding(
                probe_id=self.id,
                algorithm="PKCS8-PBES2",
                classification=Classification.SEDERHANA,
                severity=Severity.MED,
                title=f"{path.name}: encrypted PKCS#8 private key (PBES2)",
                evidence={
                    "path": str(path),
                    "format": "pkcs8-encrypted",
                    "note": ("Modern at-rest encryption, but the wrapped private "
                             "key is classical (RSA/EC) and quantum-vulnerable — "
                             "track for PQC migration."),
                },
            ))
            return

        if _LEGACY_MARK in text:
            m = _DEK_RE.search(text)
            cipher = m.group(1).upper() if m else "UNKNOWN"
            weak = any(w in cipher for w in _WEAK_CIPHERS)
            cls = Classification.TINGGI if weak else Classification.SEDERHANA
            emit(Finding(
                probe_id=self.id,
                algorithm=f"PEM-legacy/{cipher}",
                classification=cls,
                severity=_sev(cls),
                title=(f"{path.name}: legacy PEM-encrypted private key "
                       f"(DEK {cipher})"),
                evidence={
                    "path": str(path),
                    "format": "pem-legacy",
                    "cipher": cipher,
                    "note": ("Legacy PEM encryption uses a weak MD5-based KDF"
                             + (" and a broken cipher" if weak else "")
                             + "; re-encrypt as PKCS#8 PBES2. The wrapped key is "
                               "also classical and quantum-vulnerable."),
                },
            ))
