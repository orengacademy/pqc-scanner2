"""fs.keyref.cloud — cloud KMS / Key Vault / HSM key-reference discovery.

Enterprise keys increasingly live behind a managed-KMS or HSM reference rather
than on disk: AWS KMS ARNs, Azure Key Vault URLs, GCP KMS resource names, and
PKCS#11 URIs. The referenced keys are typically classical RSA/ECC
(quantum-vulnerable) and their algorithm is invisible to a file scanner, so
this probe inventories the references (plus any key-spec it can see in IaC) as
PQC-migration scope. Pure config/IaC text scan — no cloud API calls.
"""
from __future__ import annotations

import re
from pathlib import Path

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

# provider label -> reference regex
_PROVIDERS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS-KMS", re.compile(
        r"arn:aws:kms:[a-z0-9-]+:\d{12}:(?:key|alias)/[\w/+=,.@-]+")),
    ("Azure-KeyVault", re.compile(
        r"https://[a-zA-Z0-9-]+\.vault\.azure\.net/keys/[\w-]+(?:/[\w]+)?")),
    ("GCP-KMS", re.compile(
        r"projects/[\w-]+/locations/[\w-]+/keyRings/[\w-]+/cryptoKeys/[\w-]+"
        r"(?:/cryptoKeyVersions/\d+)?")),
    ("PKCS11/HSM", re.compile(r"pkcs11:[A-Za-z0-9._%;=&?/+-]+")),
]

_KEY_SPEC = re.compile(
    r"\b(RSA_(?:2048|3072|4096)|"
    r"ECC_(?:NIST_(?:P256|P384|P521)|SECG_P256K1)|"
    r"SYMMETRIC_DEFAULT)\b")

_EXTS = {
    ".tf", ".tfvars", ".hcl", ".json", ".yaml", ".yml",
    ".properties", ".env", ".conf", ".cfg", ".ini", ".toml",
}

_MAX_BYTES = 2_000_000  # skip huge files


class FsKeyrefCloud(Probe):
    """Discover cloud-KMS / Key Vault / PKCS#11 key references in configs/IaC."""

    id = "fs.keyref.cloud"
    family = ProbeFamily.FILESYSTEM
    framework_tags = ("nist-ir-8547:storage", "bukukerja:storage", "mykripto:storage")

    def __init__(self, roots: list[Path] | None = None) -> None:
        self.roots = roots or [Path("/srv"), Path("/opt"), Path("/var/www")]

    async def applies(self, ctx: ScanContext) -> bool:
        return any(r.exists() for r in self.roots)

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        for root in self.roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in _EXTS:
                    continue
                try:
                    if path.stat().st_size > _MAX_BYTES:
                        continue
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                self._scan(text, path, emit)

    def _scan(self, text: str, path: Path, emit: Emitter) -> None:
        key_specs = sorted(set(_KEY_SPEC.findall(text)))
        seen: set[tuple[str, str]] = set()
        for line_no, raw in enumerate(text.splitlines(), start=1):
            for provider, pattern in _PROVIDERS:
                for ref in pattern.findall(raw):
                    if (provider, ref) in seen:
                        continue
                    seen.add((provider, ref))
                    emit(Finding(
                        probe_id=self.id,
                        algorithm=provider,
                        classification=Classification.SEDERHANA,
                        severity=Severity.MED,
                        title=f"{provider} key reference in {path.name}",
                        evidence={
                            "path": str(path),
                            "line": line_no,
                            "provider": provider,
                            "reference": ref,
                            "key_specs": key_specs,
                            "note": ("Managed key is typically classical RSA/ECC "
                                     "(quantum-vulnerable); confirm the key spec "
                                     "and track for PQC migration."),
                        },
                    ))
